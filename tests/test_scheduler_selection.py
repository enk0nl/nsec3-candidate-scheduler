import argparse
import json

from adaptive_hashcat_scheduler.arms.base import Arm
from adaptive_hashcat_scheduler.arms.parent_domain_feedback import ParentDomainFeedbackArm
from adaptive_hashcat_scheduler.feedback.queue import FeedbackQueueState
from adaptive_hashcat_scheduler.scheduler import SchedulerContext, _feedback_availability, choose_arm, run_scheduler


def test_empty_feedback_arm_not_selected_by_forced_cadence(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {'force_every_slices': 10, 'min_slices_between_runs': 5})
    arm.last_run_adaptive_slice = 0
    choose_arm.context = ctx
    selected, _ = choose_arm([arm], 'adaptive', [], 0, __import__('random').Random(0), 10)
    assert selected is None


def test_forced_cadence_can_override_min_queue_size(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {'force_every_slices': 10, 'min_queue_size': 500})
    arm._queue(ctx).write_queue([f'c{i}' for i in range(20)])
    choose_arm.context = ctx
    selected, reason = choose_arm([arm], 'adaptive', [], 0, __import__('random').Random(0), 10)
    assert selected is arm
    assert reason == 'forced_cadence'


def test_forced_cadence_does_not_override_cooldown(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {'force_every_slices': 10, 'min_slices_between_runs': 50})
    arm._queue(ctx).write_queue(['candidate'])
    choose_arm.context = ctx
    selected, _ = choose_arm([arm], 'adaptive', [], 0, __import__('random').Random(0), 10)
    assert selected is None


def test_active_slice_makes_feedback_arm_runnable_even_with_empty_queue(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {'min_queue_size': 500})
    arm._queue(ctx).save_active_slice({'active': True, 'slice_file': 'slice_candidates.txt', 'total_candidates': 1, 'skip': 0})
    info = _feedback_availability(arm, ctx, current_adaptive_slice=0)
    assert info['available'] is True
    assert info['active_slice'] is True


def test_skipped_result_does_not_consume_completed_slice(monkeypatch, tmp_path, fake_slice_result):
    class SkippingArm(Arm):
        def __init__(self):
            super().__init__('skip', 'dictionary', {})
            self.warmup_eligible = False
        def run_slice(self, context):
            return fake_slice_result(executed=False, valid_work=False)

    class ExecutingArm(Arm):
        def __init__(self):
            super().__init__('run', 'dictionary', {})
            self.warmup_eligible = False
        def run_slice(self, context):
            with open(context.potfile, 'a', encoding='utf-8') as f:
                f.write('h1:www\n')
            return fake_slice_result(executed=True, valid_work=True, runtime_seconds=1.0)

    arms = [SkippingArm(), ExecutingArm()]
    monkeypatch.setattr('adaptive_hashcat_scheduler.scheduler.load_config', lambda path: {'alpha': 1.0, 'epsilon': 0.0, 'arms': [{'name': 'skip'}, {'name': 'run'}]})
    monkeypatch.setattr('adaptive_hashcat_scheduler.scheduler.make_arm', lambda cfg: arms[0] if cfg['name'] == 'skip' else arms[1])
    config = tmp_path / 'config.json'; config.write_text('{}', encoding='utf-8')
    hashes = tmp_path / 'hashes.txt'; hashes.write_text('hash\n', encoding='utf-8')
    out_dir = tmp_path / 'out'
    run_scheduler(argparse.Namespace(hashes=str(hashes), hash_mode=0, config=str(config), out_dir=str(out_dir),
                                     schedule='adaptive', total_slices=1, slice_seconds=1, alpha=None,
                                     epsilon=None, random_seed=0, default_limit=1000000,
                                     hashcat_bin='hashcat', quiet=True, verbose=False,
                                     no_optimized_kernels=True))
    records = [json.loads(line) for line in (out_dir / 'jobs.jsonl').read_text(encoding='utf-8').splitlines()]
    assert [record['arm'] for record in records] == ['run']
    assert arms[0].score == 0
    assert arms[1].score > 0
