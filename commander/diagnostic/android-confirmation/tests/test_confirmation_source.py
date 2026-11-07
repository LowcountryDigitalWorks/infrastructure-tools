"""Static checks for the offline confirmation diagnostic. No device is contacted."""
import hashlib
import pathlib
import unittest
import xml.etree.ElementTree as etree

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
MANIFEST = ROOT / "app" / "src" / "main" / "AndroidManifest.xml"
ACTIVITY = ROOT / "app" / "src" / "main" / "java" / "com" / "lowcountrydigitalworks" / "commander" / "diagnostic" / "ConfirmationSupportActivity.java"
STRINGS = ROOT / "app" / "src" / "main" / "res" / "values" / "strings.xml"
WORKFLOW = REPO / ".github" / "workflows" / "commander-android-confirmation.yml"
WRAPPER = ROOT / "gradle" / "wrapper" / "gradle-wrapper.jar"
WRAPPER_SHA256 = "81a82aaea5abcc8ff68b3dfcb58b3c3c429378efd98e7433460610fecd7ae45f"
NS = {"android": "http://schemas.android.com/apk/res/android"}
FORBIDDEN = (
    "presentPrompt",
    "KeyStore",
    "Keystore",
    "BiometricPrompt",
    "System.out",
    "android.util.Log",
    "HttpURLConnection",
    "INTERNET",
    "uses-permission",
    "getSerial",
    "ANDROID_ID",
    "TelephonyManager",
    "AccessibilityManager",
)


def support_label(api_level: int, supported: bool, failed: bool) -> str:
    if failed or api_level < 28:
        return "UNKNOWN"
    return "SUPPORTED" if supported else "UNSUPPORTED"


class ConfirmationSourceTests(unittest.TestCase):
    def test_manifest_has_no_permissions_and_one_launcher(self):
        root = etree.parse(MANIFEST).getroot()
        self.assertEqual(list(root.findall("uses-permission")), [])
        self.assertEqual(list(root.findall("uses-permission-sdk-23")), [])
        application = root.find("application")
        self.assertEqual(application.attrib["{http://schemas.android.com/apk/res/android}allowBackup"], "false")
        self.assertEqual(application.attrib["{http://schemas.android.com/apk/res/android}usesCleartextTraffic"], "false")
        activities = list(application.findall("activity"))
        self.assertEqual(len(activities), 1)
        self.assertEqual(activities[0].attrib["{http://schemas.android.com/apk/res/android}exported"], "true")
        self.assertEqual(list(application.findall("service")), [])
        self.assertEqual(list(application.findall("provider")), [])
        self.assertEqual(list(application.findall("receiver")), [])

    def test_activity_source_has_no_forbidden_calls(self):
        text = ACTIVITY.read_text(encoding="utf-8")
        for token in FORBIDDEN:
            self.assertNotIn(token, text)
        self.assertIn("ConfirmationPrompt.isSupported", text)
        self.assertIn("SUPPORTED", text)
        self.assertIn("UNSUPPORTED", text)
        self.assertIn("UNKNOWN", text)

    def test_caveat_is_local_and_does_not_read_accessibility(self):
        strings = STRINGS.read_text(encoding="utf-8")
        self.assertIn("accessibility service is running", strings)
        self.assertIn("does not read accessibility settings", strings)
        self.assertNotIn("turn accessibility off", strings.lower())
        self.assertNotIn("AccessibilityManager", ACTIVITY.read_text(encoding="utf-8"))

    def test_wrapper_jar_is_pinned_and_checked_before_execution(self):
        digest = hashlib.sha256(WRAPPER.read_bytes()).hexdigest()
        self.assertEqual(digest, WRAPPER_SHA256)
        workflow = WORKFLOW.read_text(encoding="utf-8")
        check = f'echo "{WRAPPER_SHA256}  gradle/wrapper/gradle-wrapper.jar" | sha256sum -c --status'
        java = "java -classpath gradle/wrapper/gradle-wrapper.jar org.gradle.wrapper.GradleWrapperMain"
        self.assertIn(check, workflow)
        self.assertLess(workflow.index(check), workflow.index(java))
        self.assertNotIn("sha256sum -c --status ||", workflow)
        self.assertIn("CHECKOUT_SHA=$(git rev-parse HEAD)", workflow)
        self.assertIn("PR_SOURCE_HEAD", workflow)

    def test_support_label_table_is_not_a_handset_result(self):
        self.assertEqual(support_label(27, True, False), "UNKNOWN")
        self.assertEqual(support_label(28, True, False), "SUPPORTED")
        self.assertEqual(support_label(36, False, False), "UNSUPPORTED")
        self.assertEqual(support_label(36, True, True), "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
