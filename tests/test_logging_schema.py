import json

from nsec3_candidate_scheduler.arms.parent_domain_feedback import ParentDomainFeedbackArm
from nsec3_candidate_scheduler.arms.static_affix_feedback import StaticAffixFeedbackArm
from nsec3_candidate_scheduler.feedback.execution import run_feedback_dictionary_slice
from tests.test_scheduler_scoring import _run_scheduler_with_wordlists


def test_feedback_job_contains_required_fields(monkeypatch, tmp_path, make_context):
    ctx = make_context(tmp_path)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {})
    state = arm._queue(ctx)
    state.write_queue(['api.test', 'test'])
    monkeypatch.setattr('nsec3_candidate_scheduler.feedback.execution.run_cmd', lambda cmd: (1, '', ''))
    result = run_feedback_dictionary_slice(arm, ctx)
    for field in [
        'feedback_state_dir', 'queue_size_before_slice', 'queue_size_after_slice', 'candidates_written_to_slice',
        'active_slice_total_candidates', 'active_slice_skip_before', 'active_slice_next_skip_after',
        'feedback_progress_source',
    ]:
        assert field in result.extra


def test_warmup_arm_local_job_contains_required_fields(tmp_path, monkeypatch):
    _, records = _run_scheduler_with_wordlists(tmp_path, monkeypatch, warmup_scoring='arm_local')
    for field in ['warmup_scoring', 'potfile_scope', 'arm_local_new_cracks', 'shared_new_cracks',
                  'marginal_new_cracks', 'duplicate_cracks_vs_shared', 'reward_used_for_score']:
        assert field in records[0]


def test_skipped_feedback_arm_not_written_as_normal_job(tmp_path, monkeypatch):
    out_dir, records = _run_scheduler_with_wordlists(
        tmp_path, monkeypatch, warmup_scoring='arm_local',
        extra_arms=[{'name': 'parent-domain', 'type': 'parent_domain_feedback', 'force_every_slices': 1}], total_slices=2,
    )
    assert all(not (record['arm'] == 'parent-domain' and record['reward'] == 0) for record in records)


def test_parent_domain_duplicate_reason_fields(tmp_path, make_context, make_fake_potfile):
    pot = make_fake_potfile(tmp_path / 'run.pot', [('h1', 'api.test')])
    ctx = make_context(tmp_path, potfile=pot)
    arm = ParentDomainFeedbackArm('parent-domain', 'parent_domain_feedback', {})
    metrics = arm.on_new_discoveries(['dev.api.test'], ctx)
    for field in ['parent_duplicates_generated', 'parent_duplicates_queued', 'parent_duplicates_already_cracked']:
        assert field in metrics


def test_static_affix_duplicate_reason_fields(tmp_path, make_context, write_lines):
    prefixes = tmp_path / 'prefixes.txt'; suffixes = tmp_path / 'suffixes.txt'
    write_lines(prefixes, ['dev']); write_lines(suffixes, ['internal'])
    ctx = make_context(tmp_path)
    arm = StaticAffixFeedbackArm('static-affix-top50', 'static_affix_feedback', {'prefixes': str(prefixes), 'suffixes': str(suffixes)})
    metrics = arm.on_new_discoveries(['api.test'], ctx)
    for field in ['affix_duplicates_generated', 'affix_duplicates_queued', 'affix_duplicates_already_cracked']:
        assert f'static-affix-top50_{field}' in metrics
