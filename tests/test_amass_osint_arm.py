import json, subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from adaptive_hashcat_scheduler.arms.amass_osint import AmassOsintArm, extract_candidates, parse_domains
from adaptive_hashcat_scheduler.scheduler import SchedulerContext, choose_arm


def arm(tmp_path, domains='example.nl', **cfg):
    dl, da = parse_domains(domains)
    c = {'name': 'amass-osint', 'type': 'amass_osint', 'amass_binary': '/home/vboxuser/go/bin/amass',
         'domains': domains, 'domains_list': dl, 'domains_arg': da, 'require_min_version': False, **cfg}
    return AmassOsintArm('amass-osint', 'amass_osint', c)


def ctx(tmp_path):
    h = tmp_path / 'hashes'; h.write_text('x\n')
    return SchedulerContext(str(h), 8300, str(tmp_path), 60, str(tmp_path / 'run.pot'))


def test_amass_osint_parses_single_domain_config():
    assert parse_domains('example.nl') == (['example.nl'], 'example.nl')


def test_amass_osint_parses_comma_separated_domains():
    assert parse_domains('example.nl, example.com') == (['example.nl', 'example.com'], 'example.nl,example.com')


def test_amass_osint_parses_list_domains():
    assert parse_domains(['example.nl', 'example.com']) == (['example.nl', 'example.com'], 'example.nl,example.com')


def test_amass_osint_starts_single_enum_process_on_run_start(tmp_path, monkeypatch):
    popen = Mock(); popen.pid = 123; popen.poll.return_value = None
    mp = Mock(return_value=popen); monkeypatch.setattr(subprocess, 'Popen', mp)
    a = arm(tmp_path); a.start(ctx(tmp_path))
    mp.assert_called_once(); assert mp.call_args.args[0] == ['/home/vboxuser/go/bin/amass', 'enum', '-d', 'example.nl']


def test_amass_osint_starts_single_process_for_multiple_domains(tmp_path, monkeypatch):
    popen = Mock(); popen.pid = 123; popen.poll.return_value = None
    mp = Mock(return_value=popen); monkeypatch.setattr(subprocess, 'Popen', mp)
    a = arm(tmp_path, 'example.nl,example.com'); a.start(ctx(tmp_path))
    mp.assert_called_once(); assert mp.call_args.args[0] == ['/home/vboxuser/go/bin/amass', 'enum', '-d', 'example.nl,example.com']


def test_amass_osint_not_available_while_running(tmp_path, monkeypatch):
    popen = Mock(); popen.pid = 123; popen.poll.return_value = None
    monkeypatch.setattr(subprocess, 'Popen', Mock(return_value=popen))
    a = arm(tmp_path); c = ctx(tmp_path); a.start(c)
    assert a.is_available(c) is False and a.state == 'running'


def test_amass_osint_fetches_subs_after_process_completion(tmp_path, monkeypatch):
    popen = Mock(); popen.pid = 123; popen.poll.return_value = 0
    monkeypatch.setattr(subprocess, 'Popen', Mock(return_value=popen))
    rc = Mock(return_value=(0, 'sub.example.nl\n', '')); monkeypatch.setattr('adaptive_hashcat_scheduler.arms.amass_osint.run_cmd', rc)
    a = arm(tmp_path); c = ctx(tmp_path); a.start(c); a.poll(c)
    rc.assert_called_once_with(['/home/vboxuser/go/bin/amass', 'subs', '-names', '-d', 'example.nl'])


def test_amass_osint_fetches_subs_once_for_multiple_domains(tmp_path, monkeypatch):
    popen = Mock(); popen.pid = 123; popen.poll.return_value = 0
    monkeypatch.setattr(subprocess, 'Popen', Mock(return_value=popen))
    rc = Mock(return_value=(0, 'www.example.nl\nwww.example.com\n', '')); monkeypatch.setattr('adaptive_hashcat_scheduler.arms.amass_osint.run_cmd', rc)
    a = arm(tmp_path, 'example.nl,example.com'); c = ctx(tmp_path); a.start(c); a.poll(c)
    rc.assert_called_once_with(['/home/vboxuser/go/bin/amass', 'subs', '-names', '-d', 'example.nl,example.com'])


def test_amass_osint_strips_base_domain_suffix():
    c, _ = extract_candidates(['sub.example.nl', 'sub.sub.example.nl'], ['example.nl'])
    assert c == ['sub', 'sub.sub']


def test_amass_osint_rejects_base_domain_itself():
    assert extract_candidates(['example.nl'], ['example.nl'])[0] == []


def test_amass_osint_rejects_names_outside_domain():
    assert extract_candidates(['otherexample.nl', 'sub.other.nl'], ['example.nl'])[0] == []


def test_amass_osint_dedupes_candidates_across_domains():
    assert extract_candidates(['www.example.nl', 'www.example.com'], ['example.nl', 'example.com'])[0] == ['www']


def test_amass_osint_uses_longest_matching_base_domain():
    assert extract_candidates(['a.sub.example.nl'], ['example.nl', 'sub.example.nl'])[0] == ['a']


def test_amass_osint_respects_include_single_label_false():
    c, _ = extract_candidates(['sub.example.nl', 'sub.sub.example.nl'], ['example.nl'], include_single_label=False)
    assert c == ['sub.sub']


def test_amass_osint_respects_include_multi_label_false():
    c, _ = extract_candidates(['sub.example.nl', 'sub.sub.example.nl'], ['example.nl'], include_multi_label=False)
    assert c == ['sub']


def complete(tmp_path, monkeypatch, output='sub.example.nl\n', domains='example.nl', **cfg):
    popen = Mock(); popen.pid = 123; popen.poll.return_value = 0
    monkeypatch.setattr(subprocess, 'Popen', Mock(return_value=popen))
    monkeypatch.setattr('adaptive_hashcat_scheduler.arms.amass_osint.run_cmd', Mock(return_value=(0, output, '')))
    a = arm(tmp_path, domains, **cfg); c = ctx(tmp_path); a.start(c); a.poll(c); return a, c


def test_amass_osint_writes_state_under_osint_dir(tmp_path, monkeypatch):
    a, _ = complete(tmp_path, monkeypatch)
    for name in ['candidates.txt', 'raw_names.txt', 'state.json', 'amass.pid', 'amass.log', 'amass.err']:
        assert (tmp_path / 'osint' / 'amass-osint' / name).exists()
        assert not (tmp_path / name).exists()


def test_amass_osint_does_not_write_per_domain_process_files(tmp_path, monkeypatch):
    complete(tmp_path, monkeypatch, domains='example.nl,example.com')
    assert not list((tmp_path / 'osint' / 'amass-osint').glob('amass_example.*'))


def test_amass_osint_ready_after_candidates_written(tmp_path, monkeypatch):
    a, c = complete(tmp_path, monkeypatch)
    assert a.state == 'ready' and a.is_available(c) and a.first_run_pending


def test_amass_osint_exhausted_when_no_candidates(tmp_path, monkeypatch):
    a, c = complete(tmp_path, monkeypatch, output='example.nl\n')
    assert a.state == 'exhausted' and not a.is_available(c) and not a.first_run_pending


def test_amass_osint_failed_on_nonzero_exit(tmp_path, monkeypatch):
    popen = Mock(); popen.pid = 123; popen.poll.return_value = 2
    monkeypatch.setattr(subprocess, 'Popen', Mock(return_value=popen))
    a = arm(tmp_path); c = ctx(tmp_path); a.start(c); a.poll(c)
    assert a.state == 'failed' and not a.is_available(c) and not a.first_run_pending


def test_amass_osint_uses_dictionary_hashcat_execution_when_ready(tmp_path, monkeypatch):
    a, c = complete(tmp_path, monkeypatch)
    run = Mock(return_value=(4, '{"status":4,"progress":[1,1],"recovered_salts":[1,1]}', ''))
    monkeypatch.setattr('adaptive_hashcat_scheduler.arms.amass_osint.run_cmd', run)
    a.run_slice(c)
    cmd = run.call_args.args[0]
    assert str(tmp_path / 'osint' / 'amass-osint' / 'candidates.txt') == cmd[-1]
    assert '--potfile-path' in cmd and str(tmp_path / 'run.pot') in cmd and '-m' in cmd and '8300' in cmd


def test_amass_osint_not_warmup_eligible(tmp_path):
    assert arm(tmp_path).warmup_eligible is False


def test_amass_osint_cleanup_terminates_running_process_by_default(tmp_path, monkeypatch):
    popen = Mock(); popen.pid = 123; popen.poll.return_value = None
    monkeypatch.setattr(subprocess, 'Popen', Mock(return_value=popen))
    a = arm(tmp_path); a.start(ctx(tmp_path)); a.cleanup(); popen.terminate.assert_called_once()


def test_amass_osint_keep_running_on_exit(tmp_path, monkeypatch):
    popen = Mock(); popen.pid = 123; popen.poll.return_value = None
    monkeypatch.setattr(subprocess, 'Popen', Mock(return_value=popen))
    a = arm(tmp_path, keep_running_on_exit=True); a.start(ctx(tmp_path)); a.cleanup(); popen.terminate.assert_not_called()


def test_amass_osint_first_run_pending_after_ready(tmp_path, monkeypatch):
    a, _ = complete(tmp_path, monkeypatch)
    assert a.state == 'ready' and a.first_run_pending


def test_scheduler_prioritizes_amass_first_run_before_epsilon(tmp_path):
    c = ctx(tmp_path); choose_arm.context = c
    a = arm(tmp_path); a.state='ready'; a.first_run_pending=True; a.wordlist_path=tmp_path/'w'; a.wordlist_path.write_text('x\n'); a.keyspace=1
    b = arm(tmp_path); b.name='other'; b.state='ready'; b.wordlist_path=tmp_path/'w2'; b.wordlist_path.write_text('x\n'); b.keyspace=1
    chosen, reason = choose_arm([a,b], 'adaptive', [], 1.0, __import__('random').Random(0), 0)
    assert chosen is a and reason == 'first_run_ready'


def test_scheduler_prioritizes_amass_first_run_before_highest_score(tmp_path):
    c = ctx(tmp_path); choose_arm.context = c
    a = arm(tmp_path); a.state='ready'; a.first_run_pending=True; a.wordlist_path=tmp_path/'w'; a.wordlist_path.write_text('x\n'); a.keyspace=1; a.score=0
    b = arm(tmp_path); b.name='pcfg'; b.state='ready'; b.wordlist_path=tmp_path/'w2'; b.wordlist_path.write_text('x\n'); b.keyspace=1; b.score=100
    chosen, reason = choose_arm([a,b], 'adaptive', [], 0.0, __import__('random').Random(0), 0)
    assert chosen is a and reason == 'first_run_ready'


def test_amass_first_run_pending_cleared_after_valid_execution(tmp_path, monkeypatch):
    a, c = complete(tmp_path, monkeypatch)
    monkeypatch.setattr('adaptive_hashcat_scheduler.arms.amass_osint.run_cmd', Mock(return_value=(4, '', '')))
    a.run_slice(c); assert not a.first_run_pending


def test_amass_first_run_pending_not_cleared_after_failed_no_progress(tmp_path, monkeypatch):
    a, c = complete(tmp_path, monkeypatch)
    monkeypatch.setattr('adaptive_hashcat_scheduler.arms.amass_osint.run_cmd', Mock(return_value=(99, '', '')))
    a.run_slice(c); assert a.first_run_pending


def test_amass_ready_during_warmup_runs_first_in_adaptive_phase(tmp_path):
    c = ctx(tmp_path); choose_arm.context = c
    a = arm(tmp_path); a.state='ready'; a.first_run_pending=True; a.wordlist_path=tmp_path/'w'; a.wordlist_path.write_text('x\n'); a.keyspace=1
    assert choose_arm([a], 'adaptive', ['warm'], 0.0, __import__('random').Random(0), 0) == (a, 'first_run_ready')


def test_run_immediately_when_ready_false_disables_first_run_priority(tmp_path, monkeypatch):
    a, _ = complete(tmp_path, monkeypatch, run_immediately_when_ready=False)
    assert a.state == 'ready' and not a.first_run_pending
