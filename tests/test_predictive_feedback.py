from adaptive_hashcat_scheduler.arms.feedback_predictive import PredictiveFeedbackArm
from adaptive_hashcat_scheduler.feedback.execution import run_feedback_dictionary_slice
from adaptive_hashcat_scheduler.feedback.train_pairs import train_directional_pairs, write_counts_tsv


def test_predictive_prefix_learns_right_to_left_pairs(tmp_path, write_lines):
    names = tmp_path / 'names.txt'
    write_lines(names, ['k2._domainkey.example'])
    prefix_counts, _, stats = train_directional_pairs(str(names), 'names')
    assert prefix_counts['_domainkey']['k2'] == 1
    assert prefix_counts['example']['_domainkey'] == 1
    assert stats['prefix_total_pairs'] == 2


def test_predictive_suffix_learns_left_to_right_pairs(tmp_path, write_lines):
    names = tmp_path / 'names.txt'
    write_lines(names, ['k2._domainkey.example'])
    _, suffix_counts, stats = train_directional_pairs(str(names), 'names')
    assert suffix_counts['k2']['_domainkey'] == 1
    assert suffix_counts['_domainkey']['example'] == 1
    assert stats['suffix_total_pairs'] == 2


def test_predictive_feedback_rejects_empty_queue_execution(tmp_path, make_context, write_lines):
    model = tmp_path / 'model.tsv'
    write_lines(model, ['api\tdev\t1'])
    ctx = make_context(tmp_path)
    arm = PredictiveFeedbackArm('predictive-prefix', 'predictive_prefix', {'model': str(model)})
    result = run_feedback_dictionary_slice(arm, ctx)
    assert result.executed is False
    assert result.execution_status == 'skipped'


def test_predictive_feedback_state_under_feedback_dir(tmp_path, make_context, write_lines, assert_no_root_feedback_files):
    model = tmp_path / 'model.tsv'
    write_lines(model, ['api\tdev\t1'])
    ctx = make_context(tmp_path)
    prefix = PredictiveFeedbackArm('predictive-prefix', 'predictive_prefix', {'model': str(model)})
    suffix = PredictiveFeedbackArm('predictive-suffix', 'predictive_suffix', {'model': str(model)})
    prefix._queue(ctx); suffix._queue(ctx)
    assert (tmp_path / 'feedback' / 'predictive-prefix').is_dir()
    assert (tmp_path / 'feedback' / 'predictive-suffix').is_dir()
    assert_no_root_feedback_files(tmp_path, 'predictive-prefix')
    assert_no_root_feedback_files(tmp_path, 'predictive-suffix')
