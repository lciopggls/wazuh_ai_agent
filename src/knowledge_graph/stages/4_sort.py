"""Stage 4: Map each triplet to its source sentence for provenance."""

import argparse
import copy
import json
import os
import os.path as op
import sys
import time

import nltk
import openai
from openai import OpenAI

_KG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _KG_ROOT)

from config import current_model, openai_api_base, openai_api_key  # noqa: E402

client = OpenAI(
    api_key=openai_api_key,
    base_url=openai_api_base,
)


class TripletsGPTSorter:
    def __init__(self, file_path, cache_path=None, gpt_model=current_model):
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            self.result_json = [data]
        else:
            self.result_json = data
        self.file_name = self.result_json[0]["file_name"]
        self.cache_path = cache_path or op.join(
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "4_sort"
            ),
            self.file_name + ".json",
        )
        self.gpt_model = gpt_model
        self.output_schema = None

    def get_triplets_with_num(
        self,
        schema_path=os.path.join(_KG_ROOT, "sort_result_schema.json"),
        model=current_model,
        use_cache=True,
    ):
        if use_cache and op.exists(self.cache_path):
            with open(self.cache_path, encoding="utf-8") as f:
                return json.load(f)

        rewriting = self.result_json[0]["rewrite"]
        sorted_triplets = []
        for tact in rewriting:
            if rewriting[tact] == "None" or rewriting[tact] is None:
                continue
            triplets_with_n = self.request_triplets_order(
                tactic=tact, schema_path=schema_path, model=model
            )
            if triplets_with_n is not None:
                sorted_triplets.extend(triplets_with_n)

        print(f"file name = {self.file_name}")
        print(
            "New count = {}, old count = {}".format(
                len(sorted_triplets), len(self.result_json[0]["triplets"])
            )
        )

        self.result_json[0]["triplets"] = sorted_triplets
        os.makedirs(op.dirname(self.cache_path), exist_ok=True)
        with open(self.cache_path, "w", encoding="utf-8") as f:
            json.dump(self.result_json, f, indent=4)
        return self.result_json

    def _dict2line(self, d):
        return (
            d["Subject"]
            + "({})".format(d["SubjectType"])
            + " ; "
            + d["Relation"]
            + " ; "
            + d["Object"]
            + "({})".format(d["ObjectType"])
        )

    def _split_sentences(self, text: str):
        sents = []
        for line in text.splitlines():
            if line:
                sents.extend(nltk.sent_tokenize(line))
        return sents

    def request_triplets_order(
        self,
        tactic=None,
        schema_path=os.path.join(_KG_ROOT, "sort_result_schema.json"),
        model=current_model,
        temperature=0,
    ):
        if tactic is None:
            return None

        triplets_tactic = [t for t in self.result_json[0]["triplets"] if t["tactic"] == tactic]
        if not triplets_tactic:
            return None

        try:
            text = self.result_json[0]["rewrite"][tactic]
        except Exception:
            return None
        if text == "None" or text is None:
            return None

        ms, tools = self.get_sort_prompt(triplets_tactic, text, schema_path, model)
        if ms is None:
            return None

        while True:
            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=ms,
                    tools=tools,
                    tool_choice="auto",
                    temperature=temperature,
                )
                triplets_with_num = copy.deepcopy(triplets_tactic)
                if response.choices[0].message.tool_calls is None:
                    return triplets_with_num

                arguments = response.choices[0].message.tool_calls[0].function.arguments
                result = json.loads(arguments)
                mapping = result["mapping"]
                for ma in mapping:
                    try:
                        id_triplet = int(ma["id_of_triplet"])
                        id_sentence = int(ma["id_of_sentence"])
                    except Exception:
                        continue
                    triplets_with_num[id_triplet]["SentenceNums"] = [id_sentence]
                return triplets_with_num
            except openai.RateLimitError:
                time.sleep(3)
            except openai.APIConnectionError:
                time.sleep(1)
            except openai.AuthenticationError as e:
                print(e)
                return None
            except openai.BadRequestError as e:
                print(e)
                return None

    def get_sort_prompt(
        self,
        triplets,
        text,
        schema_path=os.path.join(_KG_ROOT, "sort_result_schema.json"),
        model=current_model,
    ):
        if self.output_schema is None:
            with open(schema_path, encoding="utf-8") as f:
                self.output_schema = json.load(f)

        # Numbered sentences
        sents = self._split_sentences(text)
        numbered_text = "\n".join(f"{idx}: {sents[idx]}" for idx in range(len(sents)))

        # Numbered triplets
        numbered_triplets = "\n".join(
            f"{idx}: {self._dict2line(tri)}" for idx, tri in enumerate(triplets)
        )

        rules = "\n".join(
            [
                'Rule 1: Text is split into numbered sentences ("N: sentence").',
                'Rule 2: Triplets are given as "id: Entity(Type) ; Relation ; Entity(Type)".',
                "Rule 3: Output the mapping: triplet_id -> sentence_id.",
            ]
        )

        demonstration = (
            "Demonstration:\n"
            "Sentences:\n"
            "0: The attackers initially compromised a server belonging to ESTsoft, "
            "which was used to deliver software updates.\n"
            "1: Between July 18 and 25, 2011, the attackers modified the server "
            "to distribute a trojaned update file.\n\n"
            "Triplets:\n"
            "0: attackers(threat-actor) ; compromised ; server(infrastructure)\n"
            "1: server(infrastructure) ; used ; deliver software updates(course-of-action)\n"
            "2: trojaned update file(file) ; contained ; Backdoor.Agent.Hza(Malware)\n\n"
            "Mapping:\n"
            "0: attackers(threat-actor) ; compromised ; server(infrastructure):0\n"
            "1: server(infrastructure) ; used ; deliver software updates(course-of-action):0\n"
            "2: trojaned update file(file) ; contained ; Backdoor.Agent.Hza(Malware):1\n"
        )

        query = (
            f"The split sentences are:\n{numbered_text}\n\n"
            f"The triplets are:\n{numbered_triplets}\n\n"
            "The mapping of triplet to the sentence it is extracted is:\n"
        )

        messages = [
            {
                "role": "system",
                "content": (
                    "You are an assistant to label which sentence each triplet "
                    "is extracted from.\n\n" + rules + "\n\n" + demonstration
                ),
            },
            {"role": "user", "content": query},
        ]
        return messages, self.output_schema


def triplets_sorter_example(report_dir, result_dir, name_filter=None):
    os.makedirs(result_dir, exist_ok=True)
    for file_name in os.listdir(report_dir):
        if file_name.endswith(".json"):
            if name_filter and file_name[:-5] not in name_filter:
                continue
            file_path = os.path.join(report_dir, file_name)
            cache_path = os.path.join(result_dir, file_name)
            sorter = TripletsGPTSorter(file_path, cache_path=cache_path)
            sorted_result = sorter.get_triplets_with_num()
            if sorted_result:
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(sorted_result, f, indent=4)


def main():
    args = args_parser()
    name_filter = set(args.names.split(",")) if args.names else None
    triplets_sorter_example(args.report_dir, args.result_dir, name_filter)


def args_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", "-rpd", default=os.path.join(_KG_ROOT, "data", "3_label"))
    parser.add_argument("--result-dir", "-rd", default=os.path.join(_KG_ROOT, "data", "4_sort"))
    parser.add_argument("--names", default="", help="Comma-separated file base names to process")
    return parser.parse_args()


if __name__ == "__main__":
    main()
