"""Stage 3: Label each triplet with MITRE ATT&CK techniques."""

import argparse
import asyncio
import copy
import json
import os
import os.path as op
import shutil
import sys
import time

import openai
import tiktoken
from openai import OpenAI

_KG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _KG_ROOT)

from config import current_model, openai_api_base, openai_api_key  # noqa: E402
from template import mitre_technique_label_template  # noqa: E402

client = OpenAI(
    api_key=openai_api_key,
    base_url=openai_api_base,
)


def num_tokens_from_string(string: str, model_name: str) -> int:
    try:
        encoding = tiktoken.encoding_for_model(model_name)
    except KeyError:
        encoding = tiktoken.encoding_for_model("gpt-4o")
    return len(encoding.encode(string))


def async_wrap(func, args):
    return asyncio.to_thread(func, **args)


def dict2line(d, joint_char=" ; "):
    return (
        d["Subject"]
        + "({})".format(d["SubjectType"])
        + joint_char
        + d["Relation"]
        + joint_char
        + d["Object"]
        + "({})".format(d["ObjectType"])
    )


def request_technique_label(
    sents, mitre, parent_labels, model=current_model, temperature=0, max_token=120000
):
    numbered_text = "\n".join("{}: {}".format(idx, sent["sent"]) for idx, sent in enumerate(sents))
    messages, tools = mitre_technique_label_template(numbered_text, mitre, parent_labels)

    if messages is None:
        return {
            "triplets": [
                {**sent["triplet"], "technique": ["Others"], "file_name": sent["file_name"]}
                for sent in sents
            ]
        }

    num_token = sum(num_tokens_from_string(m["content"], model) for m in messages)
    if num_token > max_token:
        print("Messages skipped (token overflow)")
        return None

    tool_choice = "auto"
    while True:
        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                tools=tools,
                tool_choice=tool_choice,
                temperature=temperature,
            )
            if response.choices[0].message.tool_calls is None:
                return {
                    "triplets": [
                        {
                            **sents[idx]["triplet"],
                            "technique": ["Others"],
                            "file_name": sents[idx]["file_name"],
                        }
                        for idx in range(len(sents))
                    ]
                }

            arguments = response.choices[0].message.tool_calls[0].function.arguments
            try:
                parse_result = json.loads(arguments)
                idx2technique_label = {}
                for item in parse_result["result"]:
                    technique_label = item["technique"]
                    for idx in item["triplets_ids"]:
                        if idx2technique_label.get(idx) is None:
                            idx2technique_label[idx] = []
                        idx2technique_label[idx].append(technique_label)

                # Step 1: Deduplicate techniques within each triplet
                for idx in idx2technique_label:
                    seen = set()
                    deduped = []
                    for t in idx2technique_label[idx]:
                        if t not in seen:
                            deduped.append(t)
                            seen.add(t)
                    idx2technique_label[idx] = deduped

                # Step 2: Enforce max 3 distinct techniques per tactic batch
                MAX_TECHNIQUES = 3
                all_techs = [
                    t for techs in idx2technique_label.values() for t in techs if t != "Others"
                ]
                unique_techs = set(all_techs)
                if len(unique_techs) > MAX_TECHNIQUES:
                    tech_counts = {}
                    for t in all_techs:
                        tech_counts[t] = tech_counts.get(t, 0) + 1
                    keep_techs = set(
                        sorted(tech_counts, key=tech_counts.get, reverse=True)[:MAX_TECHNIQUES]
                    )
                    for idx in idx2technique_label:
                        filtered = []
                        seen2 = set()
                        for t in idx2technique_label[idx]:
                            t_new = t if t == "Others" or t in keep_techs else "Others"
                            if t_new not in seen2:
                                filtered.append(t_new)
                                seen2.add(t_new)
                        idx2technique_label[idx] = filtered or ["Others"]

                triplets = []
                for idx, sent in enumerate(sents):
                    triplet = copy.deepcopy(sent["triplet"])
                    triplet.update(
                        {
                            "file_name": sent["file_name"],
                            "technique": idx2technique_label.get(idx, ["Others"]),
                        }
                    )
                    triplets.append(triplet)
            except Exception:
                return None

            return {"triplets": triplets}
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


async def process_technique_files(report_dir, result_dir, mitre, request_target_files, sent_step):
    tactic_sentences = {}
    for file in request_target_files:
        file_name = file["file_name"]
        tactic_rewriting = file["rewrite"]
        for triplet in file["triplets"]:
            tactic_label = triplet["tactic"]
            sent_des = dict2line(triplet) + " " + tactic_rewriting.get(tactic_label, "")
            sent_element = {
                "sent": sent_des,
                "file_name": file_name,
                "triplet": triplet,
                "tactic": triplet["tactic"],
            }
            if tactic_sentences.get(tactic_label) is None:
                tactic_sentences[tactic_label] = []
            tactic_sentences[tactic_label].append(sent_element)

    tasks = []
    for tact in tactic_sentences:
        sentences = tactic_sentences[tact]
        for i in range(0, len(sentences), sent_step):
            s = sentences[i : i + sent_step]
            args = {"sents": s, "mitre": mitre, "parent_labels": {"tactic": tact}}
            tasks.append(async_wrap(request_technique_label, args))

    response_dicts = await asyncio.gather(*tasks)

    labeled_triplets = []
    for response_dict in response_dicts:
        if response_dict:
            labeled_triplets.extend(response_dict["triplets"])

    result_files = {}
    for l_tri in labeled_triplets:
        file_name = l_tri["file_name"]
        del l_tri["file_name"]
        if result_files.get(file_name) is None:
            result_files[file_name] = []
        result_files[file_name].append(l_tri)

    for file_name in result_files:
        file_path = op.join(result_dir, file_name + ".json")
        with open(file_path, encoding="utf-8") as f:
            result = json.load(f)
        print(
            "{}: Old count = {}, New count = {}".format(
                file_name, len(result["triplets"]), len(result_files[file_name])
            )
        )
        result["triplets"] = result_files[file_name]
        result["technique_label"] = True
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4)
    return result_files


async def async_technique_requests(
    report_dir, result_dir, mitre, file_step, sent_step, name_filter=None
):
    all_results_file = [
        f for f in os.listdir(report_dir) if name_filter is None or f[:-5] in name_filter
    ]
    all_results = []
    for i in range(0, len(all_results_file), file_step):
        f_files = all_results_file[i : i + file_step]
        request_target_files = []
        for file in f_files:
            with open(op.join(report_dir, file)) as f:
                json_attack_graph = json.load(f)
                if (
                    json_attack_graph.get("tactic_label") is not None
                    and json_attack_graph.get("technique_label") is None
                ):
                    request_target_files.append(json_attack_graph)

        results = await process_technique_files(
            report_dir, result_dir, mitre, request_target_files, sent_step
        )
        all_results.extend(v for v in results.values() if v is not None)
        print(i)
    return all_results


def main():
    args = args_parser()
    report_dir = args.report_dir
    result_dir = args.result_dir
    step = args.step
    sent_step = args.sent_step
    mitre_json_path = args.mitre_json_path

    os.makedirs(result_dir, exist_ok=True)
    shutil.copytree(report_dir, result_dir, dirs_exist_ok=True)

    with open(mitre_json_path) as f:
        mitre = json.load(f)

    name_filter = set(args.names.split(",")) if args.names else None
    asyncio.run(
        async_technique_requests(report_dir, result_dir, mitre, step, sent_step, name_filter)
    )


def args_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--report-dir", "-rpd", default=os.path.join(_KG_ROOT, "data", "2_extract") + "/"
    )
    parser.add_argument("--result-dir", "-rd", default=os.path.join(_KG_ROOT, "data", "3_label"))
    parser.add_argument("--step", "-s", default=5, type=int)
    parser.add_argument("--sent-step", "-ss", default=10, type=int)
    parser.add_argument(
        "--mitre-json-path", "-mjp", default=os.path.join(_KG_ROOT, "data", "mitre.json")
    )
    parser.add_argument("--names", default="", help="Comma-separated file base names to process")
    return parser.parse_args()


if __name__ == "__main__":
    main()
