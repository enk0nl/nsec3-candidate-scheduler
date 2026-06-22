import json, subprocess, random
from unittest.mock import Mock
import pytest

from adaptive_hashcat_scheduler.config import load_config
from adaptive_hashcat_scheduler.arms.amass_osint import extract_candidates as amass_extract
from adaptive_hashcat_scheduler.arms.subfinder_osint import SubfinderOsintArm, extract_candidates
from adaptive_hashcat_scheduler.scheduler import SchedulerContext, choose_arm, _availability


def ctx(tmp_path):
    h = tmp_path / 'hashes'; h.write_text('x\n')
    return SchedulerContext(str(h), 8300, str(tmp_path), 60, str(tmp_path / 'run.pot'))


def arm(**cfg):
    c = {'name': 'subfinder-osint', 'type': 'subfinder_osint', 'subfinder_binary': '/home/vboxuser/go/bin/subfinder',
         'domain': 'example.nl', **cfg}
    return SubfinderOsintArm(c['name'], 'subfinder_osint', c)


def cfgfile(tmp_path, arm_cfg):
    p=tmp_path/'config.json'; p.write_text(json.dumps({'arms':[arm_cfg]})); return str(p)


def test_subfinder_osint_requires_domain(tmp_path):
    with pytest.raises(ValueError, match='subfinder_osint arm requires non-empty domain'):
        load_config(cfgfile(tmp_path, {'name':'s','type':'subfinder_osint'}))


def test_subfinder_osint_parses_single_domain_config(tmp_path):
    cfg=load_config(cfgfile(tmp_path, {'name':'s','type':'subfinder_osint','domain':'Example.NL.'}))
    assert cfg['arms'][0]['domain'] == 'example.nl'


def test_subfinder_osint_starts_process_on_run_start(tmp_path, monkeypatch):
    popen=Mock(); popen.pid=123; popen.poll.return_value=None
    mp=Mock(return_value=popen); monkeypatch.setattr(subprocess, 'Popen', mp)
    a=arm(); a.start(ctx(tmp_path))
    mp.assert_called_once(); assert mp.call_args.args[0] == ['/home/vboxuser/go/bin/subfinder','-silent','-d','example.nl']


def test_subfinder_osint_not_available_while_running(tmp_path, monkeypatch):
    popen=Mock(); popen.pid=123; popen.poll.return_value=None
    monkeypatch.setattr(subprocess, 'Popen', Mock(return_value=popen))
    a=arm(); c=ctx(tmp_path); a.start(c)
    info=_availability(a,c,0)
    assert info['available'] is False and info['runnable'] is False and info['availability_reason']=='osint_running'


def complete(tmp_path, monkeypatch, output='sub.example.nl\nsub.sub.example.nl\n', rc=0, **cfg):
    popen=Mock(); popen.pid=123; popen.poll.return_value=rc
    monkeypatch.setattr(subprocess, 'Popen', Mock(return_value=popen))
    a=arm(**cfg); c=ctx(tmp_path); a.start(c)
    (tmp_path/'osint'/'subfinder-osint'/'subfinder.log').write_text(output)
    a.poll(c); return a,c


def test_subfinder_osint_collects_stdout_after_completion(tmp_path, monkeypatch):
    complete(tmp_path, monkeypatch)
    assert (tmp_path/'osint'/'subfinder-osint'/'raw_names.txt').read_text().splitlines()==['sub.example.nl','sub.sub.example.nl']


def test_subfinder_osint_strips_base_domain_suffix():
    assert extract_candidates(['sub.example.nl','sub.sub.example.nl'], ['example.nl'])[0] == ['sub','sub.sub']


def test_subfinder_osint_rejects_base_domain_itself():
    assert extract_candidates(['example.nl'], ['example.nl'])[0] == []


def test_subfinder_osint_rejects_names_outside_domain():
    assert extract_candidates(['otherexample.nl','sub.other.nl'], ['example.nl'])[0] == []


def test_subfinder_osint_respects_include_single_label_false():
    assert extract_candidates(['sub.example.nl','sub.sub.example.nl'], ['example.nl'], include_single_label=False)[0] == ['sub.sub']


def test_subfinder_osint_respects_include_multi_label_false():
    assert extract_candidates(['sub.example.nl','sub.sub.example.nl'], ['example.nl'], include_multi_label=False)[0] == ['sub']


def test_subfinder_osint_dedupes_candidates():
    assert extract_candidates(['www.example.nl','www.example.nl.','WWW.EXAMPLE.NL'], ['example.nl'])[0] == ['www']


def test_subfinder_osint_respects_max_candidates(tmp_path, monkeypatch):
    complete(tmp_path, monkeypatch, output='a.example.nl\nb.example.nl\nc.example.nl\n', max_candidates=2)
    assert (tmp_path/'osint'/'subfinder-osint'/'candidates.txt').read_text().splitlines()==['a','b']


def test_subfinder_osint_writes_state_under_osint_dir(tmp_path, monkeypatch):
    complete(tmp_path, monkeypatch)
    for name in ['candidates.txt','raw_names.txt','state.json','subfinder.pid','subfinder.log','subfinder.err']:
        assert (tmp_path/'osint'/'subfinder-osint'/name).exists()
        assert not (tmp_path/name).exists()


def test_subfinder_osint_ready_after_candidates_written(tmp_path, monkeypatch):
    a,c=complete(tmp_path, monkeypatch)
    assert a.state=='ready' and a.is_available(c) and a.first_run_pending


def test_subfinder_osint_exhausted_when_no_candidates(tmp_path, monkeypatch):
    a,c=complete(tmp_path, monkeypatch, output='example.nl\n')
    assert a.state=='exhausted' and not a.is_available(c) and not a.first_run_pending


def test_subfinder_osint_failed_on_nonzero_exit(tmp_path, monkeypatch):
    a,c=complete(tmp_path, monkeypatch, rc=2)
    assert a.state=='failed' and not a.is_available(c) and not a.first_run_pending


def test_subfinder_osint_uses_dictionary_hashcat_execution_when_ready(tmp_path, monkeypatch):
    a,c=complete(tmp_path, monkeypatch)
    run=Mock(return_value=(4,'{"status":4,"progress":[1,1],"recovered_salts":[1,1]}',''))
    monkeypatch.setattr('adaptive_hashcat_scheduler.arms.subfinder_osint.run_cmd', run)
    a.run_slice(c); cmd=run.call_args.args[0]
    assert str(tmp_path/'osint'/'subfinder-osint'/'candidates.txt') == cmd[-1]
    assert '--potfile-path' in cmd and str(tmp_path/'run.pot') in cmd and '-m' in cmd and '8300' in cmd


def test_subfinder_osint_not_warmup_eligible(): assert arm().warmup_eligible is False


def test_subfinder_osint_cleanup_terminates_running_process_by_default(tmp_path, monkeypatch):
    popen=Mock(); popen.pid=123; popen.poll.return_value=None; monkeypatch.setattr(subprocess,'Popen',Mock(return_value=popen))
    a=arm(); a.start(ctx(tmp_path)); a.cleanup(); popen.terminate.assert_called_once()


def test_subfinder_osint_keep_running_on_exit(tmp_path, monkeypatch):
    popen=Mock(); popen.pid=123; popen.poll.return_value=None; monkeypatch.setattr(subprocess,'Popen',Mock(return_value=popen))
    a=arm(keep_running_on_exit=True); a.start(ctx(tmp_path)); a.cleanup(); popen.terminate.assert_not_called()


def test_subfinder_osint_first_run_pending_after_ready(tmp_path, monkeypatch):
    assert complete(tmp_path, monkeypatch)[0].first_run_pending


def ready_arm(tmp_path, name='subfinder-osint'):
    a=arm(name=name); a.state='ready'; a.first_run_pending=True; a.wordlist_path=tmp_path/name; a.wordlist_path.write_text('x\n'); a.keyspace=1; return a


def test_scheduler_prioritizes_subfinder_first_run_before_epsilon(tmp_path):
    c=ctx(tmp_path); choose_arm.context=c
    a=ready_arm(tmp_path); b=ready_arm(tmp_path,'other'); b.first_run_pending=False
    chosen,reason=choose_arm([a,b], 'adaptive', [], 1.0, random.Random(0), 0)
    assert chosen is a and reason=='first_run_ready'


def test_scheduler_prioritizes_subfinder_first_run_before_highest_score(tmp_path):
    c=ctx(tmp_path); choose_arm.context=c
    a=ready_arm(tmp_path); b=ready_arm(tmp_path,'pcfg'); b.first_run_pending=False; b.score=100
    chosen,reason=choose_arm([a,b], 'adaptive', [], 0.0, random.Random(0), 0)
    assert chosen is a and reason=='first_run_ready'


def test_subfinder_first_run_pending_cleared_after_valid_execution(tmp_path, monkeypatch):
    a,c=complete(tmp_path, monkeypatch); monkeypatch.setattr('adaptive_hashcat_scheduler.arms.subfinder_osint.run_cmd', Mock(return_value=(4,'','')))
    a.run_slice(c); assert not a.first_run_pending


def test_subfinder_first_run_pending_not_cleared_after_failed_no_progress(tmp_path, monkeypatch):
    a,c=complete(tmp_path, monkeypatch); monkeypatch.setattr('adaptive_hashcat_scheduler.arms.subfinder_osint.run_cmd', Mock(return_value=(99,'','')))
    a.run_slice(c); assert a.first_run_pending


def test_subfinder_ready_during_warmup_runs_first_in_adaptive_phase(tmp_path):
    c=ctx(tmp_path); choose_arm.context=c; a=ready_arm(tmp_path)
    assert choose_arm([a], 'adaptive', ['warm'], 0.0, random.Random(0), 0) == (a,'first_run_ready')


def test_run_immediately_when_ready_false_disables_first_run_priority(tmp_path, monkeypatch):
    a,_=complete(tmp_path, monkeypatch, run_immediately_when_ready=False)
    assert a.state=='ready' and not a.first_run_pending


def test_osint_suffix_stripping_helper_shared_with_amass():
    raw=['sub.example.nl','sub.sub.example.nl']
    assert amass_extract(raw, ['example.nl'])[0] == extract_candidates(raw, ['example.nl'])[0]
