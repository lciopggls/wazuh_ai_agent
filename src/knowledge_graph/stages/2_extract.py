"""Stage 2: Extract security triplets from rewritten text, with noise filtering."""

import argparse
import asyncio
import json
import os
import os.path as op
import re
import sys
import time

import openai
import tiktoken
from openai import OpenAI

_KG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _KG_ROOT)

from config import current_model, openai_api_base, openai_api_key  # noqa: E402
from template import Tactic_label_order, attack_graph_template  # noqa: E402

client = OpenAI(
    api_key=openai_api_key,
    base_url=openai_api_base,
)

# ---- Noise entity patterns & normalization (applied before saving) ----
EXCLUDE_PATTERNS = [
    r"^(detection\s+)?rules?\s*[\d,\s]+$",
    r"^alert\s*[\d,\s]+$",
    r"^signature\s*[\d,\s]+$",
]

EXCLUDE_TYPES = {"technique", "attack-pattern", "Tactic", "Technique"}


def _normalize_entity_name(name: str) -> str:
    """Truncate paths to last component: a/b/c → c."""
    if "\\" in name or "/" in name:
        return re.split(r"[\\/]", name)[-1]
    return name


def _is_noise_entity(name: str) -> bool:
    name_lower = name.strip().lower()
    return any(re.match(p, name_lower) for p in EXCLUDE_PATTERNS)


def _filter_triplets(triplets: list) -> list:
    """Remove noise and normalize entity names."""
    clean = []
    for t in triplets:
        if (
            t.get("SubjectType", "") in EXCLUDE_TYPES
            or t.get("ObjectType", "") in EXCLUDE_TYPES
            or _is_noise_entity(t.get("Subject", ""))
            or _is_noise_entity(t.get("Object", ""))
        ):
            continue
        t["Subject"] = _normalize_entity_name(t["Subject"])
        t["Object"] = _normalize_entity_name(t["Object"])
        clean.append(t)
    return clean


# -----------------------------------------------------------


def num_tokens_from_string(string: str, model_name: str) -> int:
    try:
        encoding = tiktoken.encoding_for_model(model_name)
    except Exception:
        encoding = tiktoken.encoding_for_model("gpt-4o")
    return len(encoding.encode(string))


def async_wrap(func, args):
    return asyncio.to_thread(func, **args)


def line2dict(line: str):
    strings = line.replace("\n", "")
    strings = re.sub(r"^\d+\.", "", strings).strip()
    strings = re.sub(r"^\*", "", strings).strip()
    strings = strings.split(";")
    if len(strings) != 4:
        print("Format is wrong, line is skipped:")
        print(line, "\n")
        return None
    Sub_block = strings[0].strip()
    Obj_block = strings[2].strip()
    return {
        "Subject": Sub_block.split("(")[0],
        "SubjectType": Sub_block.split("(")[-1].replace(")", ""),
        "Relation": strings[1].strip(),
        "Object": Obj_block.split("(")[-1].replace(")", ""),
    }


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


def check_triplet(triplet: dict):
    for key in ["Subject", "SubjectType", "Relation", "Object", "ObjectType"]:
        if triplet.get(key) is None:
            triplet[key] = "Others"
    return triplet


def request_attack_graph(bags, tactic="None", model=current_model, temperature=0, max_token=120000):
    if len(bags) == 0:
        raise Exception("Empty bags list")

    bag_text = ""
    id2name = {}
    for bag in bags:
        bag_text += "article {}:\n".format(bag["file_id"]) + bag["text"] + "\n\n"
        id2name[bag["file_id"]] = bag["file_name"]

    messages, tools = attack_graph_template(bag_text)
    tool_choice = "auto"

    num_token = sum(num_tokens_from_string(m["content"], model) for m in messages)
    if num_token > max_token:
        print("Messages skipped (token overflow)")
        return None

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
                id_from_first_bag = list(id2name.keys())[0]
                text_content = response.choices[0].message.content
                arguments_dict = {"triplets": []}
                for line_text in text_content.split("\n"):
                    d = line2dict(line_text)
                    if d:
                        d.update(
                            {"file_id": id_from_first_bag, "technique": ["T0000-Fake Technique"]}
                        )
                        arguments_dict["triplets"].append(d)
                arguments = json.dumps(arguments_dict)
            else:
                arguments = response.choices[0].message.tool_calls[0].function.arguments

            try:
                parse_result = json.loads(arguments)
                triplets = parse_result["triplets"]
                result = []
                for triplet in triplets:
                    file_id = triplet["file_id"]
                    triplet.update({"tactic": tactic, "file_name": id2name[file_id]})
                    del triplet["file_id"]
                    triplet = check_triplet(triplet)
                    result.append(triplet)
            except Exception:
                return None

            return {"triplets": result, "tactic": tactic}
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
        except Exception as e:
            print(e)
            return None


async def process_files(report_dir, save_dir, file_idxes, file_names):
    results = {}
    for name in file_names:
        results[name] = {"triplets": [], "file_name": name, "tactic_label": True}

    tactic_bags = {}
    for i, file_name in enumerate(file_names):
        with open(op.join(report_dir, file_name + ".json"), encoding="utf-8") as f:
            rewrite_dict = json.load(f)
        if not isinstance(rewrite_dict, dict):
            continue
        results[file_name].update({"rewrite": rewrite_dict})

        for tactic in rewrite_dict:
            text = rewrite_dict[tactic]
            if text == "None" or text is None:
                continue
            if tactic_bags.get(tactic) is None:
                tactic_bags[tactic] = []
            tactic_bags[tactic].append(
                {"file_id": file_idxes[i], "file_name": file_name, "text": text}
            )

    tasks = []
    for tactic in tactic_bags:
        args = {"bags": tactic_bags[tactic], "tactic": tactic, "model": current_model}
        tasks.append(async_wrap(request_attack_graph, args))

    response_dicts = await asyncio.gather(*tasks)

    for response_dict in response_dicts:
        if response_dict is None:
            continue
        for triplet in response_dict["triplets"]:
            file_name = triplet["file_name"]
            del triplet["file_name"]
            results[file_name]["triplets"].append(triplet)

    # Filter noise entities, remove Others, cap at 32 per file with balanced tactic distribution
    MAX_TRIPLETS = 32
    for file_name in results:
        triplets = _filter_triplets(results[file_name]["triplets"])
        # Split: valid tactics vs Others (Others discarded — not used in visualization)
        valid = [t for t in triplets if t.get("tactic", "") != "Others"]
        if len(valid) > MAX_TRIPLETS:
            # Group by tactic and evenly trim each to fit within 40
            by_tactic = {}
            for t in valid:
                by_tactic.setdefault(t["tactic"], []).append(t)
            per_tactic_limit = max(1, MAX_TRIPLETS // len(by_tactic))
            trimmed = []
            for tact in sorted(by_tactic, key=lambda x: Tactic_label_order.get(x, 99)):
                trimmed.extend(by_tactic[tact][:per_tactic_limit])
            valid = trimmed[:MAX_TRIPLETS]
        results[file_name]["triplets"] = valid

    # Save
    for file_name in results:
        save_path = op.join(save_dir, file_name + ".json")
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(results[file_name], f, indent=4)
    return results


async def async_requests(report_dir, save_dir, file_idxes, all_reports_name, step, current_model):
    all_results = []
    for i in range(0, len(all_reports_name), step):
        f_names = all_reports_name[i : i + step]
        f_idxes = file_idxes[i : i + step]
        results = await process_files(report_dir, save_dir, f_idxes, f_names)
        for res in results.values():
            if res is not None:
                all_results.append(res)
        print(i)
    return all_results


def main():
    args = args_parser()
    report_dir = args.report_dir
    save_dir = args.save_dir
    step = args.step

    os.makedirs(save_dir, exist_ok=True)

    name_filter = set(args.names.split(",")) if args.names else None
    all_reports_name = []
    for file in os.listdir(report_dir):
        if not file.endswith("json"):
            continue
        name = file[:-5]
        if name_filter and name not in name_filter:
            continue
        if op.exists(op.join(save_dir, name + ".json")):
            continue
        all_reports_name.append(name)

    file_idxs = list(range(len(all_reports_name)))
    t = time.time()
    asyncio.run(
        async_requests(report_dir, save_dir, file_idxs, all_reports_name, step, current_model)
    )
    print(f"actual time = {time.time() - t:.2f}s")


def args_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", "-rd", default=os.path.join(_KG_ROOT, "data", "1_rewrite"))
    parser.add_argument("--save-dir", "-sd", default=os.path.join(_KG_ROOT, "data", "2_extract"))
    parser.add_argument("--step", "-s", type=int, default=5)
    parser.add_argument("--names", default="", help="Comma-separated file base names to process")
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    main()
