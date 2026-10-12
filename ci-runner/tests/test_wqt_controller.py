"""Python contract guard tests for WQT Stage A1 controller capability."""
from pathlib import Path
import re
import unittest

PSM1_PATH = Path(__file__).parents[1] / "CiRunner.psm1"


class WqtControllerContractGuards(unittest.TestCase):
    def setUp(self):
        self.psm1_content = PSM1_PATH.read_text(encoding="utf-8")

    def test_wqt_operations_in_authorized_profiles(self):
        self.assertIn("LowcountryDigitalWorks/wqt-operations", self.psm1_content)
        self.assertIn(".github/workflows/wqt.yml", self.psm1_content)
        self.assertIn(".github/workflows/wqt-semantic-consumer.yml", self.psm1_content)
        self.assertIn("validate-pr", self.psm1_content)
        self.assertIn("retention-probe-pr", self.psm1_content)

    def test_pattern_matching_refused(self):
        self.assertIn("PATTERN_MATCHING_REFUSED", self.psm1_content)
        self.assertIn("WORKLOAD_PROFILE_NOT_AUTHORIZED", self.psm1_content)

    def test_run_attempt_and_dependency_guards_present(self):
        self.assertIn("RUN_ATTEMPT_MISMATCH", self.psm1_content)
        self.assertIn("DEPENDENCY_NOT_SATISFIED", self.psm1_content)

    def test_no_unlisted_jobs_or_wildcards_allowed(self):
        # Match AuthorizedProfiles block in PowerShell script
        profiles_block = re.search(r"\$script:AuthorizedProfiles\s*=\s*@\((.*?)\)\n\n", self.psm1_content, re.DOTALL)
        self.assertIsNotNone(profiles_block)
        block_text = profiles_block.group(1)

        # Check exact job targets in profiles block
        target_jobs = re.findall(r"TargetJob\s*=\s*'([^']+)'", block_text)
        self.assertEqual(sorted(target_jobs), ["retention-probe-pr", "validate-pr", "validate-pr"])

        # Check exact workflow paths
        workflow_paths = re.findall(r"WorkflowPath\s*=\s*'([^']+)'", block_text)
        self.assertIn(".github/workflows/wqt.yml", workflow_paths)
        self.assertIn(".github/workflows/wqt-semantic-consumer.yml", workflow_paths)
        self.assertIn(".github/workflows/security-secrets.yml", workflow_paths)
        self.assertIn(".github/workflows/ci-runner-isolation-proof.yml", workflow_paths)


if __name__ == "__main__":
    unittest.main()
