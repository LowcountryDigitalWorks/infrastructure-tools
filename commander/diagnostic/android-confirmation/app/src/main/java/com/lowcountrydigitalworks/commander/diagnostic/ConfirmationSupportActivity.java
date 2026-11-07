package com.lowcountrydigitalworks.commander.diagnostic;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.security.ConfirmationPrompt;
import android.widget.Button;
import android.widget.TextView;

public final class ConfirmationSupportActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_confirmation_support);
        Button check = findViewById(R.id.check_support);
        TextView status = findViewById(R.id.support_status);
        check.setOnClickListener(view -> status.setText(readSupport()));
    }

    private String readSupport() {
        int api = Build.VERSION.SDK_INT;
        try {
            if (api < 28) {
                return "UNKNOWN\nAPI " + api;
            }
            boolean supported = ConfirmationPrompt.isSupported(getApplicationContext());
            return (supported ? "SUPPORTED" : "UNSUPPORTED") + "\nAPI " + api;
        } catch (Throwable ignored) {
            return "UNKNOWN\nAPI " + api;
        }
    }
}
