import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.sentinelgrid.defense',
  appName: 'SentinelGrid Defense',
  webDir: 'dist',
  server: {
    androidScheme: 'https',
    cleartext: true,
  },
  plugins: {
    // Deep linking and custom scheme callback for Google OAuth Redirect
    App: {
      urlScheme: 'com.sentinelgrid.defense',
    },
  },
};

export default config;
