package com.sentinelgrid.defense;

import android.os.Bundle;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(SentinelDeviceGuardPlugin.class);
        super.onCreate(savedInstanceState);
    }
}
