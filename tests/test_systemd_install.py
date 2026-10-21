"""Validate service rendering without installing or starting host services."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "deploy/systemd/install.py"
SPEC = importlib.util.spec_from_file_location("systemd_install", MODULE_PATH)
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


class SystemdInstallTests(unittest.TestCase):
    def test_systemd_values_escape_spaces_specifiers_and_exec_expansion(self):
        self.assertEqual(INSTALLER.systemd_quote('/srv/AI project/100%'), '"/srv/AI project/100%%"')
        self.assertEqual(INSTALLER.systemd_quote('/opt/$NODE/bin/node', executable=True), '"/opt/$$NODE/bin/node"')
        self.assertEqual(INSTALLER.systemd_quote('a"b\\c'), '"a\\"b\\\\c"')

    def test_reject_multiline_paths(self):
        for value in ('/srv/app\nUser=root', '/srv/app\r', '/srv/app\x00'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                INSTALLER.systemd_quote(value)

    def test_units_keep_venv_interpreter_and_application_import_path(self):
        project = Path('/srv/AI project')
        python = project / '.venv/bin/python'
        node = Path('/opt/node/bin/node')
        units = INSTALLER.render_units(project, python, node, 1001, 1002)
        backend = units['wazuh-memory.service']
        self.assertIn('ExecStart=' + INSTALLER.systemd_quote(python, executable=True) + ' -u -m src.service.memory', backend)
        self.assertIn('Environment=' + INSTALLER.systemd_quote('PYTHONPATH=' + str(project / 'src')), backend)
        self.assertIn('WorkingDirectory=' + INSTALLER.systemd_quote(project), backend)
        self.assertIn('User=1001\nGroup=1002', backend)
        for unit in units.values():
            self.assertNotRegex(unit, r'@[A-Z_]+@')
            self.assertNotIn('\r', unit)

    def test_frontend_keeps_proxy_server_on_fixed_port(self):
        units = INSTALLER.render_units(Path('/srv/app'), '/srv/app/.venv/bin/python', '/opt/node/bin/node', 1001, 1001)
        frontend = units['wazuh-frontend.service']
        self.assertIn('node_modules/vite/bin/vite.js --host 0.0.0.0 --port 8112 --strictPort', frontend)
        self.assertIn('After=network-online.target wazuh-memory.service', frontend)
        self.assertNotIn('preview', frontend)
        self.assertNotIn('langgraph', frontend)
        for unit in units.values():
            self.assertIn('Restart=on-failure', unit)
            self.assertIn('WantedBy=multi-user.target', unit)

    def test_atomic_write_replaces_only_destination_and_leaves_no_temp_files(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'wazuh-memory.service'
            destination.write_text('old', encoding='utf-8')
            INSTALLER.atomic_write(destination, '[Service]\nUser=1001\n')
            self.assertEqual(destination.read_bytes(), b'[Service]\nUser=1001\n')
            self.assertEqual(list(Path(folder).iterdir()), [destination])


if __name__ == '__main__':
    unittest.main()
