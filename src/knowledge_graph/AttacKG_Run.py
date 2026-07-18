"""AttacKG+ Knowledge Graph Pipeline — one command from CTI report to HTML graph.

Usage: python AttacKG_Run.py [input_dir] [save_subdir]
  input_dir:   optional custom input dir (default: data/input/)
  save_subdir: optional subdirectory under output/ (default: output)
"""
import subprocess
import os
import sys
import shutil

_KG_ROOT = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(os.path.dirname(_KG_ROOT))

# Parse args
input_dir = sys.argv[1] if len(sys.argv) > 1 else ''
save_subdir = sys.argv[2] if len(sys.argv) > 2 else ''

# Resolve input directory
default_input = os.path.join(_KG_ROOT, 'input')
active_dir = input_dir if input_dir else default_input
src_dir = active_dir if os.path.isabs(active_dir) else os.path.join(_PROJECT_ROOT, active_dir)
source_names = ','.join(
    os.path.splitext(f)[0] for f in os.listdir(src_dir)
    if f.endswith(('.txt', '.md', '.pdf'))
) if os.path.isdir(src_dir) else ''

scripts = [
    'stages/1_rewrite.py',
    'stages/2_extract.py',
    'stages/3_label.py',
    'stages/4_sort.py',
]

script_args = {
    'stages/1_rewrite.py': ['--input-dir', active_dir] if input_dir else [],
    'stages/2_extract.py': ['--names', source_names] if source_names else [],
    'stages/3_label.py': ['--names', source_names] if source_names else [],
    'stages/4_sort.py': ['--names', source_names] if source_names else [],
}

# ---- Stage 1-4: extraction pipeline ----
for script in scripts:
    script_path = os.path.join(_KG_ROOT, script)
    command = [sys.executable, '-B', script_path] + script_args.get(script, [])
    print(f'Running {script}...')
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        print(f'Error running {script}:')
        print(result.stderr)
        sys.exit(1)
    else:
        print(f'{script} completed successfully.')
        print(result.stdout)

# ---- Stage 5: visualization ----
print('\n=== Generating visualizations ===')

vis_cache_dir = os.path.join(_KG_ROOT, 'data', 'vis_cache')
result_dir = os.path.join(_KG_ROOT, 'data', '4_sort')
save_dir = os.path.join(_KG_ROOT, 'output', save_subdir)

os.makedirs(vis_cache_dir, exist_ok=True)
os.makedirs(save_dir, exist_ok=True)

if _KG_ROOT not in sys.path:
    sys.path.insert(0, _KG_ROOT)

from visualization import draw_one_pic

name_set = set(source_names.split(',')) if source_names else None
for file in os.listdir(result_dir):
    if not file.endswith('.json'):
        continue
    name = file[:-5]
    if name_set and name not in name_set:
        continue

    shutil.copy2(os.path.join(result_dir, file), os.path.join(vis_cache_dir, file))

    try:
        draw_one_pic(vis_cache_dir, name, save_dir=save_dir)
        print(f'  Generated: {name}.html')
    except Exception as e:
        print(f'  Failed: {name} - {e}')

print('\nDone.')
