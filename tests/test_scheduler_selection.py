import argparse
import json

from nsec3_candidate_scheduler.arms.base import Arm
from nsec3_candidate_scheduler.arms.parent_domain_feedback import ParentDomainFeedbackArm
from nsec3_candidate_scheduler.feedback.queue import FeedbackQueueState
from nsec3_candidate_scheduler.scheduler import SchedulerContext, _feedback_availability, choose_arm, run_scheduler


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
    arm.last_run_global_slice = 0
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
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.load_config', lambda path: {'alpha': 1.0, 'epsilon': 0.0, 'arms': [{'name': 'skip'}, {'name': 'run'}]})
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.make_arm', lambda cfg: arms[0] if cfg['name'] == 'skip' else arms[1])
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


def test_warmup_slices_count_toward_feedback_force_interval(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {'force_every_slices': 10, 'min_slices_between_runs': 5})
    arm._queue(ctx).write_queue(['candidate'])
    choose_arm.context = ctx
    selected, reason = choose_arm([arm], 'adaptive', [], 0, __import__('random').Random(0), current_adaptive_slice=0, global_valid_slice_index=10)
    assert selected is arm
    assert reason == 'forced_cadence'


def test_warmup_and_adaptive_slices_both_count_toward_feedback_force_interval(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {'force_every_slices': 10})
    arm._queue(ctx).write_queue(['candidate'])
    choose_arm.context = ctx
    selected, reason = choose_arm([arm], 'adaptive', [], 0, __import__('random').Random(0), current_adaptive_slice=7, global_valid_slice_index=10)
    assert selected is arm
    assert reason == 'forced_cadence'


def test_warmup_slices_count_toward_feedback_cooldown(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {'min_slices_between_runs': 5})
    arm.last_run_global_slice = 0
    arm._queue(ctx).write_queue(['candidate'])
    info = _feedback_availability(arm, ctx, global_valid_slice_index=5)
    assert info['cooldown_satisfied'] is True
    assert info['slices_since_last_run'] == 5


def test_invalid_jobs_do_not_count_toward_feedback_cadence(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {'force_every_slices': 10})
    arm._queue(ctx).write_queue(['candidate'])
    choose_arm.context = ctx
    selected, reason = choose_arm([arm], 'adaptive', [], 0, __import__('random').Random(0), current_adaptive_slice=10, global_valid_slice_index=7)
    assert selected is arm
    assert reason != 'forced_cadence'


def test_never_run_feedback_arm_not_treated_as_ran_at_zero(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {'force_every_slices': 10, 'min_slices_between_runs': 5})
    arm._queue(ctx).write_queue(['candidate'])
    info = _feedback_availability(arm, ctx, global_valid_slice_index=3)
    assert info['cooldown_satisfied'] is True
    assert info['slices_since_last_run'] is None
    choose_arm.context = ctx
    selected, _ = choose_arm([arm], 'adaptive', [], 0, __import__('random').Random(0), current_adaptive_slice=3, global_valid_slice_index=3)
    assert selected is arm  # normal runnable feedback is available, but not forced by interval yet
    assert getattr(arm, 'last_availability')['cadence_basis'] == 'global_valid_slices'


def test_feedback_run_updates_last_run_global_slice(tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {'min_slices_between_runs': 5})
    arm.last_run_global_slice = 10
    info = _feedback_availability(arm, ctx, global_valid_slice_index=13)
    assert info['slices_since_last_run'] == 3
    assert info['cooldown_satisfied'] is False


def test_adaptive_counter_remains_adaptive_only(monkeypatch, tmp_path, fake_slice_result):
    class ValidArm(Arm):
        def __init__(self, name, warmup_eligible=True):
            super().__init__(name, 'dictionary', {})
            self.warmup_eligible = warmup_eligible
        def run_slice(self, context):
            return fake_slice_result(executed=True, valid_work=True, runtime_seconds=1.0)

    arms = [ValidArm(f'warm{i}') for i in range(3)] + [ValidArm('adaptive-a', warmup_eligible=False), ValidArm('adaptive-b', warmup_eligible=False)]
    by_name = {arm.name: arm for arm in arms}
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.load_config', lambda path: {'alpha': 1.0, 'epsilon': 0.0, 'arms': [{'name': arm.name} for arm in arms]})
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.make_arm', lambda cfg: by_name[cfg['name']])
    config = tmp_path / 'config.json'; config.write_text('{}', encoding='utf-8')
    hashes = tmp_path / 'hashes.txt'; hashes.write_text('hash\n', encoding='utf-8')
    out_dir = tmp_path / 'out'
    run_scheduler(argparse.Namespace(hashes=str(hashes), hash_mode=0, config=str(config), out_dir=str(out_dir),
                                     schedule='adaptive', total_slices=5, slice_seconds=1, alpha=None,
                                     epsilon=None, random_seed=0, default_limit=1000000,
                                     hashcat_bin='hashcat', quiet=True, verbose=False,
                                     no_optimized_kernels=True))
    records = [json.loads(line) for line in (out_dir / 'jobs.jsonl').read_text(encoding='utf-8').splitlines()]
    assert records[-1]['global_valid_slice_index'] == 5
    assert records[-1]['current_adaptive_slice'] == 2
    assert [record['current_adaptive_slice'] for record in records[:3]] == [0, 0, 0]


def test_jobs_jsonl_reports_global_cadence_basis_for_feedback(monkeypatch, tmp_path, fake_slice_result, make_context):
    class ValidWarmupArm(Arm):
        def __init__(self):
            super().__init__('warm', 'dictionary', {})
        def run_slice(self, context):
            return fake_slice_result(executed=True, valid_work=True, runtime_seconds=1.0)

    class ValidFeedbackArm(ParentDomainFeedbackArm):
        def __init__(self):
            super().__init__('parent-domain', 'parent_domain_feedback', {'force_every_slices': 1, 'min_slices_between_runs': 0})
        def run_slice(self, context):
            return fake_slice_result(executed=True, valid_work=True, runtime_seconds=1.0)

    warm = ValidWarmupArm()
    feedback = ValidFeedbackArm()
    arms = {'warm': warm, 'parent-domain': feedback}
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.load_config', lambda path: {'alpha': 1.0, 'epsilon': 0.0, 'arms': [{'name': 'warm'}, {'name': 'parent-domain'}]})
    monkeypatch.setattr('nsec3_candidate_scheduler.scheduler.make_arm', lambda cfg: arms[cfg['name']])
    config = tmp_path / 'config.json'; config.write_text('{}', encoding='utf-8')
    hashes = tmp_path / 'hashes.txt'; hashes.write_text('hash\n', encoding='utf-8')
    out_dir = tmp_path / 'out'
    # Populate the feedback queue under the scheduler output directory before the feedback arm is selected.
    ctx = make_context(out_dir)
    feedback._queue(ctx).write_queue(['candidate'])
    run_scheduler(argparse.Namespace(hashes=str(hashes), hash_mode=0, config=str(config), out_dir=str(out_dir),
                                     schedule='adaptive', total_slices=2, slice_seconds=1, alpha=None,
                                     epsilon=None, random_seed=0, default_limit=1000000,
                                     hashcat_bin='hashcat', quiet=True, verbose=False,
                                     no_optimized_kernels=True))
    records = [json.loads(line) for line in (out_dir / 'jobs.jsonl').read_text(encoding='utf-8').splitlines()]
    feedback_record = next(record for record in records if record['arm'] == 'parent-domain')
    assert feedback_record['selection_reason'] == 'forced_cadence'
    assert feedback_record['global_valid_slice_index'] == 2
    assert feedback_record['last_run_global_slice'] == 1
    assert feedback_record['slices_since_last_run'] == 1
    assert feedback_record['forced_cadence_interval'] == 1
    assert feedback_record['cadence_basis'] == 'global_valid_slices'
    assert feedback_record['cooldown_satisfied'] is True
