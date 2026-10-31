"""Comprehensive Test Suite for Agent 2 (Network Anomaly Detection).

Tests artifact integrity, strict 74-feature validation, real Isolation Forest inference,
error handling safeguards, failure modes, and Agent 3 contract serialization.
"""

import json
import math
import sys
import unittest
import warnings
from pathlib import Path
from unittest.mock import MagicMock

# Ensure src is on the Python path
PROJECT_SRC = Path(__file__).resolve().parent.parent.parent / "src"
if str(PROJECT_SRC) not in sys.path:
    sys.path.insert(0, str(PROJECT_SRC))

import numpy as np

from dark_trace.agent2 import (
    Agent2,
    Agent2Config,
    NetworkFlowInput,
    AnomalyScore,
    Agent2Evidence,
    IsolationForestDetector,
    create_disabled_threat_intel_payload,
)


class TestAgent2Artifacts(unittest.TestCase):
    """Artifact tests: verify real trained artifacts and metadata exported from Colab."""

    def setUp(self):
        self.config = Agent2Config()

    def test_artifacts_exist(self):
        """Verify that all three trained model artifacts exist on disk."""
        self.assertTrue(self.config.model_path.is_file(), f"Missing model: {self.config.model_path}")
        self.assertTrue(self.config.metadata_path.is_file(), f"Missing metadata: {self.config.metadata_path}")
        self.assertTrue(self.config.evaluation_path.is_file(), f"Missing evaluation: {self.config.evaluation_path}")

    def test_metadata_parses_successfully(self):
        """Verify metadata JSON structure, configuration, and threshold."""
        with open(self.config.metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        self.assertEqual(meta.get("model"), "IsolationForest")
        self.assertIn("configuration", meta)
        self.assertEqual(meta["configuration"].get("n_estimators"), 300)
        self.assertEqual(meta["configuration"].get("max_samples"), 1024)
        self.assertEqual(meta["configuration"].get("random_state"), 42)

        # Calibrated threshold verification
        threshold = meta.get("threshold")
        self.assertIsNotNone(threshold)
        self.assertAlmostEqual(threshold, 0.47685521147215626, places=8)

        # Feature names count
        feature_names = meta.get("feature_names", [])
        self.assertEqual(len(feature_names), 74)
        self.assertEqual(meta.get("feature_count"), 74)

    def test_model_loads_successfully(self):
        """Verify IsolationForestDetector loads the joblib model and sets is_loaded=True."""
        detector = IsolationForestDetector(
            model_path=self.config.model_path,
            metadata_path=self.config.metadata_path,
        )
        self.assertTrue(detector.is_loaded())
        self.assertEqual(detector.expected_feature_count, 74)
        self.assertAlmostEqual(detector.threshold, 0.47685521147215626, places=8)

    def test_feature_count_and_order_match_model(self):
        """Verify feature count and names on detector match scikit-learn's feature_names_in_."""
        detector = IsolationForestDetector()
        self.assertTrue(detector.is_loaded())
        self.assertEqual(len(detector.feature_names), 74)
        self.assertEqual(detector.model.n_features_in_, 74)

        if hasattr(detector.model, "feature_names_in_"):
            self.assertEqual(list(detector.model.feature_names_in_), detector.feature_names)

    def test_evaluation_report_matches_colab_facts(self):
        """Verify evaluation metrics in agent2_final_evaluation.json."""
        with open(self.config.evaluation_path, "r", encoding="utf-8") as f:
            eval_data = json.load(f)

        eval_metrics = eval_data.get("evaluation", {})
        self.assertEqual(eval_metrics.get("true_positives"), 33046)
        self.assertEqual(eval_metrics.get("false_positives"), 2931)
        self.assertEqual(eval_metrics.get("true_negatives"), 57070)
        self.assertEqual(eval_metrics.get("false_negatives"), 21138)
        self.assertAlmostEqual(eval_metrics.get("precision"), 0.9185312838758095, places=5)
        self.assertAlmostEqual(eval_metrics.get("recall"), 0.6098848368522073, places=5)
        self.assertAlmostEqual(eval_metrics.get("f1"), 0.7330442208937346, places=5)
        self.assertAlmostEqual(eval_metrics.get("balanced_accuracy"), 0.7805178255026524, places=5)
        self.assertAlmostEqual(eval_metrics.get("false_positive_rate"), 0.04884918584690255, places=5)
        self.assertAlmostEqual(eval_metrics.get("roc_auc"), 0.9094309766696073, places=5)
        self.assertAlmostEqual(eval_metrics.get("average_precision"), 0.8276907947110725, places=5)


class TestDeepFeatureValidation(unittest.TestCase):
    """Deep feature validation tests covering all 14 required cases."""

    def setUp(self):
        self.detector = IsolationForestDetector()
        self.valid_features = {f: 0.0 for f in self.detector.feature_names}

    def test_case_1_valid_dict_all_74_features(self):
        """Case 1: A valid dictionary containing all 74 features."""
        matrix = self.detector.validate_features(self.valid_features)
        self.assertEqual(matrix.shape, (1, 74))
        self.assertEqual(matrix.dtype, np.float64)

    def test_case_2_valid_features_different_dictionary_order(self):
        """Case 2: Valid features supplied in a different dictionary order are correctly ordered."""
        distinct_vals = {name: float(i + 1) for i, name in enumerate(self.detector.feature_names)}
        reversed_dict = {k: distinct_vals[k] for k in reversed(list(distinct_vals.keys()))}

        matrix = self.detector.validate_features(reversed_dict)
        expected = np.array([[float(i + 1) for i in range(74)]], dtype=np.float64)
        np.testing.assert_array_equal(matrix, expected)

    def test_case_3_one_missing_required_feature(self):
        """Case 3: One missing required feature raises ValueError."""
        incomplete = dict(self.valid_features)
        del incomplete["Flow Duration"]

        with self.assertRaises(ValueError) as ctx:
            self.detector.validate_features(incomplete)
        self.assertIn("Missing 1 required features", str(ctx.exception))
        self.assertIn("Flow Duration", str(ctx.exception))

    def test_case_4_multiple_missing_required_features(self):
        """Case 4: Multiple missing required features raise ValueError."""
        incomplete = dict(self.valid_features)
        del incomplete["Flow Duration"]
        del incomplete["Destination Port"]
        del incomplete["Total Fwd Packets"]

        with self.assertRaises(ValueError) as ctx:
            self.detector.validate_features(incomplete)
        self.assertIn("Missing 3 required features", str(ctx.exception))

    def test_case_5_unexpected_extra_features(self):
        """Case 5: Unexpected extra features are safely ignored while extracting all 74 required features."""
        extra_dict = dict(self.valid_features)
        extra_dict["unrelated_sensor_field"] = "sensor_42"
        extra_dict["extra_score"] = 999.0
        extra_dict["extra_meta"] = {"key": "val"}

        matrix = self.detector.validate_features(extra_dict)
        self.assertEqual(matrix.shape, (1, 74))

    def test_case_6_numeric_strings_supported(self):
        """Case 6: Valid numeric strings are cleanly converted to float."""
        numeric_str_dict = dict(self.valid_features)
        numeric_str_dict["Destination Port"] = "443"
        numeric_str_dict["Flow Duration"] = "125000.5"

        matrix = self.detector.validate_features(numeric_str_dict)
        self.assertEqual(matrix[0, 0], 443.0)
        self.assertEqual(matrix[0, 1], 125000.5)

    def test_case_7_non_numeric_strings_rejected(self):
        """Case 7: Non-numeric strings raise ValueError."""
        bad_val = dict(self.valid_features)
        bad_val["Destination Port"] = "https_port"

        with self.assertRaises(ValueError) as ctx:
            self.detector.validate_features(bad_val)
        self.assertIn("non-numeric value", str(ctx.exception).lower())

    def test_case_8_nan_values_rejected(self):
        """Case 8: NaN values (float and string) raise ValueError."""
        # Float NaN
        bad_float_nan = dict(self.valid_features)
        bad_float_nan["Flow Duration"] = float("nan")
        with self.assertRaises(ValueError) as ctx:
            self.detector.validate_features(bad_float_nan)
        self.assertIn("NaN", str(ctx.exception))

        # String NaN
        bad_str_nan = dict(self.valid_features)
        bad_str_nan["Flow Duration"] = "nan"
        with self.assertRaises(ValueError) as ctx:
            self.detector.validate_features(bad_str_nan)
        self.assertIn("NaN", str(ctx.exception))

    def test_case_9_positive_infinity_rejected(self):
        """Case 9: Positive infinity (float and string) raises ValueError."""
        bad_pos_inf = dict(self.valid_features)
        bad_pos_inf["Flow Duration"] = float("inf")
        with self.assertRaises(ValueError) as ctx:
            self.detector.validate_features(bad_pos_inf)
        self.assertIn("infinite", str(ctx.exception).lower())

        bad_str_inf = dict(self.valid_features)
        bad_str_inf["Flow Duration"] = "inf"
        with self.assertRaises(ValueError) as ctx:
            self.detector.validate_features(bad_str_inf)
        self.assertIn("infinite", str(ctx.exception).lower())

    def test_case_10_negative_infinity_rejected(self):
        """Case 10: Negative infinity (float and string) raises ValueError."""
        bad_neg_inf = dict(self.valid_features)
        bad_neg_inf["Flow Duration"] = float("-inf")
        with self.assertRaises(ValueError) as ctx:
            self.detector.validate_features(bad_neg_inf)
        self.assertIn("infinite", str(ctx.exception).lower())

        bad_str_neg_inf = dict(self.valid_features)
        bad_str_neg_inf["Flow Duration"] = "-inf"
        with self.assertRaises(ValueError) as ctx:
            self.detector.validate_features(bad_str_neg_inf)
        self.assertIn("infinite", str(ctx.exception).lower())

    def test_case_11_empty_input_rejected(self):
        """Case 11: Empty dictionary input raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            self.detector.validate_features({})
        self.assertIn("Missing 74 required features", str(ctx.exception))

    def test_case_12_incorrect_input_structure_rejected(self):
        """Case 12: Non-dictionary inputs (None, list, string, bool) raise ValueError."""
        with self.assertRaises(ValueError) as ctx:
            self.detector.validate_features(None)
        self.assertIn("must be provided as a dictionary", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            self.detector.validate_features([1.0, 2.0])
        self.assertIn("must be provided as a dictionary", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            self.detector.validate_features("not_a_dict")
        self.assertIn("must be provided as a dictionary", str(ctx.exception))

        # Boolean feature values inside dict must also be rejected
        bool_dict = dict(self.valid_features)
        bool_dict["Flow Duration"] = True
        with self.assertRaises(ValueError) as ctx:
            self.detector.validate_features(bool_dict)
        self.assertIn("boolean value", str(ctx.exception))

    def test_case_13_incorrect_feature_count(self):
        """Case 13: Incomplete feature dictionary raises ValueError identifying missing count."""
        partial_dict = {f: 1.0 for f in list(self.detector.feature_names)[:40]}
        with self.assertRaises(ValueError) as ctx:
            self.detector.validate_features(partial_dict)
        self.assertIn("Missing 34 required features", str(ctx.exception))

    def test_case_14_very_large_and_small_values(self):
        """Case 14: Very large (1e308) and very small (1e-308, 0.0) values are handled; overflow (1e309) rejected."""
        # 1e308 and 1e-308 pass finite float validation
        large_dict = {f: 1e308 for f in self.detector.feature_names}
        matrix_large = self.detector.validate_features(large_dict)
        self.assertEqual(matrix_large.shape, (1, 74))

        small_dict = {f: 1e-308 for f in self.detector.feature_names}
        matrix_small = self.detector.validate_features(small_dict)
        self.assertEqual(matrix_small.shape, (1, 74))

        # Overflow beyond float64 (1e309 evaluates to inf) must be rejected
        overflow_dict = dict(self.valid_features)
        overflow_dict["Flow Duration"] = "1e309"
        with self.assertRaises(ValueError) as ctx:
            self.detector.validate_features(overflow_dict)
        self.assertIn("infinite", str(ctx.exception).lower())


class TestInference(unittest.TestCase):
    """Inference tests: real model scoring, threshold comparison, and output values."""

    def setUp(self):
        self.detector = IsolationForestDetector()
        self.benign_features = {f: 0.0 for f in self.detector.feature_names}
        self.anomalous_features = {f: 1e8 for f in self.detector.feature_names}

    def test_real_model_inference_executes(self):
        """Verify inference returns an AnomalyScore with status=EVALUATED."""
        score = self.detector.predict_anomaly(self.benign_features)
        self.assertIsInstance(score, AnomalyScore)
        self.assertEqual(score.status, "EVALUATED")
        self.assertIn(score.is_anomaly, [True, False])
        self.assertIsNotNone(score.raw_score)
        self.assertTrue(math.isfinite(score.raw_score))
        self.assertGreaterEqual(score.inference_latency_ms, 0.0)

    def test_score_uses_negative_score_samples(self):
        """Verify anomaly score convention: score = -model.score_samples(X)."""
        score = self.detector.predict_anomaly(self.benign_features)
        X = self.detector.validate_features(self.benign_features)
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UserWarning)
            expected_score = float(-self.detector.model.score_samples(X)[0])
        self.assertAlmostEqual(score.raw_score, expected_score, places=7)

    def test_threshold_comparison(self):
        """Verify is_anomaly is True when score >= threshold, False when score < threshold."""
        benign_score = self.detector.predict_anomaly(self.benign_features)
        self.assertEqual(benign_score.is_anomaly, benign_score.raw_score >= self.detector.threshold)
        self.assertFalse(benign_score.is_anomaly)

        anomalous_score = self.detector.predict_anomaly(self.anomalous_features)
        self.assertEqual(anomalous_score.is_anomaly, anomalous_score.raw_score >= self.detector.threshold)
        self.assertTrue(anomalous_score.is_anomaly)

    def test_threshold_boundary_behavior(self):
        """Verify boundary condition: score >= threshold is anomalous, score < threshold is normal."""
        calibrated_t = 0.47685521147215626

        # Score exactly at threshold
        score_at_threshold = AnomalyScore(
            status="EVALUATED",
            is_anomaly=(calibrated_t >= calibrated_t),
            raw_score=calibrated_t,
            threshold=calibrated_t,
        )
        self.assertTrue(score_at_threshold.is_anomaly)
        self.assertEqual(score_at_threshold.anomaly_label, "ANOMALOUS")

        # Score slightly above threshold (+1e-9)
        score_above = AnomalyScore(
            status="EVALUATED",
            is_anomaly=((calibrated_t + 1e-9) >= calibrated_t),
            raw_score=calibrated_t + 1e-9,
            threshold=calibrated_t,
        )
        self.assertTrue(score_above.is_anomaly)
        self.assertEqual(score_above.anomaly_label, "ANOMALOUS")

        # Score slightly below threshold (-1e-9)
        score_below = AnomalyScore(
            status="EVALUATED",
            is_anomaly=((calibrated_t - 1e-9) >= calibrated_t),
            raw_score=calibrated_t - 1e-9,
            threshold=calibrated_t,
        )
        self.assertFalse(score_below.is_anomaly)
        self.assertEqual(score_below.anomaly_label, "NORMAL")

    def test_normalized_score_is_none(self):
        """Verify normalized_score is None (not falsely represented as a probability)."""
        score = self.detector.predict_anomaly(self.benign_features)
        self.assertIsNone(score.normalized_score)

    def test_supporting_features_empty(self):
        """Verify supporting_features is empty list (no fabricated attribution)."""
        score = self.detector.predict_anomaly(self.benign_features)
        self.assertEqual(score.supporting_features, [])


class TestFailureModes(unittest.TestCase):
    """Failure tests: verify safe failure modes and exception handling."""

    def test_missing_model_artifact_raises(self):
        """Verify FileNotFoundError if model artifact does not exist."""
        with self.assertRaises(FileNotFoundError):
            IsolationForestDetector(model_path=Path("/tmp/nonexistent_model.joblib"))

    def test_missing_metadata_artifact_raises(self):
        """Verify FileNotFoundError if metadata file does not exist."""
        cfg = Agent2Config()
        with self.assertRaises(FileNotFoundError):
            IsolationForestDetector(
                model_path=cfg.model_path,
                metadata_path=Path("/tmp/nonexistent_meta.json"),
            )

    def test_corrupt_model_artifact_raises(self):
        """Verify RuntimeError if model artifact is corrupted."""
        cfg = Agent2Config()
        corrupt_path = Path("/tmp/corrupt_model.joblib")
        corrupt_path.write_bytes(b"corrupted_bytes_not_a_pickle")
        try:
            with self.assertRaises(RuntimeError):
                IsolationForestDetector(
                    model_path=corrupt_path,
                    metadata_path=cfg.metadata_path,
                )
        finally:
            if corrupt_path.exists():
                corrupt_path.unlink()

    def test_invalid_metadata_threshold_raises(self):
        """Verify ValueError if metadata threshold is negative or non-numeric."""
        bad_meta_path = Path("/tmp/bad_threshold_metadata.json")
        bad_meta = {
            "model": "IsolationForest",
            "threshold": -0.5,
            "feature_names": ["feat_" + str(i) for i in range(74)],
            "feature_count": 74,
        }
        bad_meta_path.write_text(json.dumps(bad_meta), encoding="utf-8")
        cfg = Agent2Config()
        try:
            with self.assertRaises(ValueError) as ctx:
                IsolationForestDetector(
                    model_path=cfg.model_path,
                    metadata_path=bad_meta_path,
                )
            self.assertIn("threshold must be positive", str(ctx.exception))
        finally:
            if bad_meta_path.exists():
                bad_meta_path.unlink()

    def test_model_not_ready_behavior(self):
        """Verify unloaded detector behaves safely and returns MODEL_NOT_READY with is_anomaly=None."""
        detector = IsolationForestDetector.__new__(IsolationForestDetector)
        detector.model = None
        detector.feature_names = []
        detector.threshold = None
        self.assertFalse(detector.is_loaded())

        with self.assertRaises(RuntimeError):
            detector.predict_anomaly({"test": 1.0})

        # Agent coordinator with unloaded detector
        agent = Agent2(model=detector)
        flow = NetworkFlowInput(flow_id="unloaded-flow", features={})
        evidence = agent.analyze_flow(flow)
        ev_dict = agent.format_for_agent3(evidence)

        self.assertEqual(ev_dict["anomaly_evidence"]["status"], "MODEL_NOT_READY")
        self.assertIsNone(ev_dict["anomaly_evidence"]["is_anomaly"])
        self.assertEqual(ev_dict["anomaly_evidence"]["anomaly_label"], "UNKNOWN")
        self.assertIsNone(ev_dict["anomaly_evidence"]["raw_score"])

    def test_agent2_initialization_with_missing_model_does_not_crash(self):
        """Verify Agent2 gracefully initializes in MODEL_NOT_READY state if default model path is missing."""
        cfg_missing = Agent2Config(base_dir=Path("/tmp/nonexistent_agent2_root"))
        agent = Agent2(config=cfg_missing)
        self.assertFalse(agent.model.is_loaded())

        flow = NetworkFlowInput(flow_id="missing-model-flow", features={})
        evidence = agent.analyze_flow(flow)
        ev_dict = agent.format_for_agent3(evidence)
        self.assertEqual(ev_dict["anomaly_evidence"]["status"], "MODEL_NOT_READY")
        self.assertIsNone(ev_dict["anomaly_evidence"]["is_anomaly"])

    def test_invalid_input_error_handling(self):
        """Verify invalid input does not crash pipeline and yields VALIDATION_ERROR with is_anomaly=None."""
        agent = Agent2()
        bad_flow = NetworkFlowInput(flow_id="bad-flow", features={"missing": 1.0})
        evidence = agent.analyze_flow(bad_flow)
        ev_dict = agent.format_for_agent3(evidence)

        self.assertEqual(ev_dict["anomaly_evidence"]["status"], "VALIDATION_ERROR")
        self.assertIsNone(ev_dict["anomaly_evidence"]["is_anomaly"])
        self.assertEqual(ev_dict["anomaly_evidence"]["anomaly_label"], "UNKNOWN")
        self.assertIn("error_message", ev_dict["anomaly_evidence"])

    def test_none_flow_input_handled_safely(self):
        """Verify passing None as flow input does not crash and returns INVALID_INPUT status."""
        agent = Agent2()
        evidence = agent.analyze_flow(None)
        ev_dict = agent.format_for_agent3(evidence)

        self.assertEqual(ev_dict["anomaly_evidence"]["status"], "INVALID_INPUT")
        self.assertIsNone(ev_dict["anomaly_evidence"]["is_anomaly"])
        self.assertEqual(ev_dict["anomaly_evidence"]["anomaly_label"], "UNKNOWN")
        self.assertEqual(ev_dict["flow_id"], "unknown")

    def test_dict_flow_input_handled_safely(self):
        """Verify passing a raw dict as flow input is parsed and scored successfully."""
        agent = Agent2()
        sample_feats = {f: 0.0 for f in agent.model.feature_names}
        flow_dict = {
            "flow_id": "dict-flow-1",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 12345,
            "dst_port": 80,
            "protocol": "TCP",
            "features": sample_feats,
        }
        evidence = agent.analyze_flow(flow_dict)
        ev_dict = agent.format_for_agent3(evidence)

        self.assertEqual(ev_dict["flow_id"], "dict-flow-1")
        self.assertEqual(ev_dict["anomaly_evidence"]["status"], "EVALUATED")
        self.assertFalse(ev_dict["anomaly_evidence"]["is_anomaly"])

    def test_inference_exception_error_handling(self):
        """Verify unexpected inference error yields INFERENCE_ERROR with is_anomaly=None."""
        mock_detector = MagicMock(spec=IsolationForestDetector)
        mock_detector.is_loaded.return_value = True
        mock_detector.predict_anomaly.side_effect = RuntimeError("Estimator tree traversal failed")
        mock_detector.threshold = 0.47685521
        mock_detector.model_version = "mock"

        agent = Agent2(model=mock_detector)
        flow = NetworkFlowInput(flow_id="error-flow", features={})
        evidence = agent.analyze_flow(flow)
        ev_dict = agent.format_for_agent3(evidence)

        self.assertEqual(ev_dict["anomaly_evidence"]["status"], "INFERENCE_ERROR")
        self.assertIsNone(ev_dict["anomaly_evidence"]["is_anomaly"])
        self.assertEqual(ev_dict["anomaly_evidence"]["anomaly_label"], "UNKNOWN")
        self.assertIn("Estimator tree traversal failed", ev_dict["anomaly_evidence"]["error_message"])


class TestAgent3Contract(unittest.TestCase):
    """Agent 3 contract tests: verify evidence package structure, labels, and disabled threat intel."""

    def setUp(self):
        self.agent = Agent2()
        self.sample_features = {f: 0.0 for f in self.agent.model.feature_names}

    def test_agent3_contract_structure(self):
        """Verify required fields in Agent2Evidence payload."""
        flow = NetworkFlowInput(
            flow_id="flow-agent3-contract-1",
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            protocol="TCP",
            features=self.sample_features,
        )

        evidence = self.agent.analyze_flow(flow)
        payload = self.agent.format_for_agent3(evidence)

        # Core handover keys
        self.assertEqual(payload["agent_id"], "A2")
        self.assertEqual(payload["flow_id"], "flow-agent3-contract-1")
        self.assertIn("timestamp", payload)
        self.assertIn("anomaly_evidence", payload)
        self.assertIn("threat_intelligence", payload)
        self.assertIn("routing_metadata", payload)

        # Anomaly evidence keys
        anom = payload["anomaly_evidence"]
        self.assertEqual(anom["status"], "EVALUATED")
        self.assertIn("is_anomaly", anom)
        self.assertIn("anomaly_label", anom)
        self.assertEqual(anom["anomaly_label"], "NORMAL")
        self.assertIn("raw_score", anom)
        self.assertIn("normalized_score", anom)
        self.assertIn("anomaly_score", anom)
        self.assertIn("threshold", anom)
        self.assertIn("decision_threshold", anom)
        self.assertEqual(anom["threshold"], anom["decision_threshold"])
        self.assertIn("model_version", anom)
        self.assertIn("supporting_features", anom)
        self.assertIn("inference_latency_ms", anom)

        # Routing metadata keys
        routing = payload["routing_metadata"]
        self.assertEqual(routing["src_ip"], "192.168.1.50")
        self.assertEqual(routing["dst_ip"], "10.0.0.1")
        self.assertEqual(routing["src_port"], 54321)
        self.assertEqual(routing["dst_port"], 80)
        self.assertEqual(routing["protocol"], "TCP")

    def test_threat_intelligence_is_disabled_and_unfabricated(self):
        """Verify threat_intelligence payload indicates DISABLED with empty findings."""
        ti_payload = create_disabled_threat_intel_payload()
        self.assertEqual(ti_payload["status"], "DISABLED")
        self.assertEqual(ti_payload["investigation_status"], "NOT_APPLICABLE")
        self.assertFalse(ti_payload["is_enriched"])
        self.assertEqual(ti_payload["findings"], [])
        self.assertEqual(ti_payload["sources"], [])

        flow = NetworkFlowInput(flow_id="ti-check", features=self.sample_features)
        evidence = self.agent.analyze_flow(flow)
        ev_dict = self.agent.format_for_agent3(evidence)
        self.assertEqual(ev_dict["threat_intelligence"]["status"], "DISABLED")
        self.assertEqual(ev_dict["threat_intelligence"]["investigation_status"], "NOT_APPLICABLE")
        self.assertFalse(ev_dict["threat_intelligence"]["is_enriched"])

    def test_no_false_normal_verdict_on_failure(self):
        """Verify is_anomaly is never reported as False when an error occurs."""
        agent = Agent2()
        # Missing features triggers validation error
        bad_flow = NetworkFlowInput(flow_id="fail-flow", features={})
        evidence = agent.analyze_flow(bad_flow)
        ev_dict = agent.format_for_agent3(evidence)

        self.assertNotEqual(
            ev_dict["anomaly_evidence"]["is_anomaly"],
            False,
            "Must never report False (normal) on evaluation error",
        )
        self.assertIsNone(ev_dict["anomaly_evidence"]["is_anomaly"])
        self.assertEqual(ev_dict["anomaly_evidence"]["anomaly_label"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
