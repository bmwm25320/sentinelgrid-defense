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
    App: {
      urlScheme: 'com.sentinelgrid.defense',
    },
    SocialLogin: {
      google: {
        webClientId: '693966093694-s9sa9fuhdbbl197a7461sml1u5bleq6s.apps.googleusercontent.com',
      },
    },
  },
};

export default config;
