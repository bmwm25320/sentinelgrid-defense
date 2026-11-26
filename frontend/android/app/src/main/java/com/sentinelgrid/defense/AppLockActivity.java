package com.sentinelgrid.defense;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.OnBackPressedCallback;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import java.util.concurrent.Executor;

/**
 * Biometric & PIN Lock Gate rendered when opening a SentinelGrid-protected app.
 */
public class AppLockActivity extends AppCompatActivity {

    public static final String EXTRA_TARGET_PACKAGE = "target_package";
    private String targetPackage = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        targetPackage = getIntent().getStringExtra(EXTRA_TARGET_PACKAGE);
        if (targetPackage == null) targetPackage = "";

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        root.setBackgroundColor(Color.parseColor("#070B14"));
        root.setPadding(64, 64, 64, 64);

        TextView title = new TextView(this);
        title.setText("SentinelGrid App Lock");
        title.setTextColor(Color.WHITE);
        title.setTextSize(20f);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("Protected app: " + targetPackage);
        sub.setTextColor(Color.parseColor("#34D399"));
        sub.setTextSize(13f);
        sub.setGravity(Gravity.CENTER);
        sub.setPadding(0, 12, 0, 32);
        root.addView(sub);

        EditText pinInput = new EditText(this);
        pinInput.setHint("Enter Vault / App Lock PIN (default 1234)");
        pinInput.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        pinInput.setTextColor(Color.WHITE);
        pinInput.setHintTextColor(Color.parseColor("#64748B"));
        pinInput.setGravity(Gravity.CENTER);
        root.addView(pinInput);

        Button unlockBtn = new Button(this);
        unlockBtn.setText("Unlock with PIN");
        unlockBtn.setBackgroundColor(Color.parseColor("#10B981"));
        unlockBtn.setTextColor(Color.BLACK);
        unlockBtn.setOnClickListener(v -> {
            SharedPreferences prefs = getSharedPreferences(NotificationPhishingService.PREFS_NAME, Context.MODE_PRIVATE);
            String expectedPin = prefs.getString(AppLockService.KEY_LOCK_PIN, "1234");
            if (expectedPin.equals(pinInput.getText().toString().trim())) {
                AppLockService.markTemporarilyUnlocked(targetPackage);
                finish();
            } else {
                Toast.makeText(this, "Incorrect PIN", Toast.LENGTH_SHORT).show();
            }
        });
        root.addView(unlockBtn);

        Button bioBtn = new Button(this);
        bioBtn.setText("Use Fingerprint / Biometrics");
        bioBtn.setOnClickListener(v -> promptBiometric());
        root.addView(bioBtn);

        setContentView(root);
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                // Prevent bypassing App Lock with Android Back button: send safely to Home screen
                Intent home = new Intent(Intent.ACTION_MAIN);
                home.addCategory(Intent.CATEGORY_HOME);
                home.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(home);
                finish();
            }
        });
        promptBiometric();
    }

    private void promptBiometric() {
        BiometricManager bm = BiometricManager.from(this);
        if (bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK) != BiometricManager.BIOMETRIC_SUCCESS) {
            return;
        }
        Executor executor = ContextCompat.getMainExecutor(this);
        BiometricPrompt prompt = new BiometricPrompt(
            this,
            executor,
            new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    AppLockService.markTemporarilyUnlocked(targetPackage);
                    finish();
                }
            }
        );
        BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
            .setTitle("SentinelGrid App Lock")
            .setSubtitle("Authenticate to access " + targetPackage)
            .setNegativeButtonText("Use PIN")
            .build();
        prompt.authenticate(info);
    }
}
