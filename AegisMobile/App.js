import React, { useState, useRef } from 'react';
import {
  StyleSheet,
  View,
  ActivityIndicator,
  SafeAreaView,
  StatusBar,
  BackHandler,
  Platform,
  Alert,
  Text,
  TouchableOpacity
} from 'react-native';
import { WebView } from 'react-native-webview';

// ── CONFIGURATION ──
const AEGIS_URL = 'https://sayarbhattacharyya68-ai-aegis-portal-main-pwa-install.streamlit.app/';

export default function App() {
  const webViewRef = useRef(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  // Handle Android Hardware Back Button
  React.useEffect(() => {
    const onBackPress = () => {
      if (webViewRef.current) {
        webViewRef.current.goBack();
        return true; // Prevent default behavior
      }
      return false;
    };

    BackHandler.addEventListener('hardwareBackPress', onBackPress);
    return () => BackHandler.removeEventListener('hardwareBackPress', onBackPress);
  }, []);

  const handleReload = () => {
    setError(false);
    setLoading(true);
    webViewRef.current?.reload();
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#080D24" />

      <WebView
        ref={webViewRef}
        source={{ uri: AEGIS_URL }}
        style={styles.webview}
        onLoadStart={() => setLoading(true)}
        onLoadEnd={() => setLoading(false)}
        onError={() => setError(true)}
        javaScriptEnabled={true}
        domStorageEnabled={true}
        allowsBackForwardNavigationGestures={true}
        pullToRefreshEnabled={true}
        // User Agent spoofing to ensure mobile layout
        userAgent="Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36 AegisMobile/1.0"
      />

      {/* Loading Overlay */}
      {loading && !error && (
        <View style={styles.overlay}>
          <ActivityIndicator size="large" color="#94FBAB" />
          <Text style={styles.loadingText}>SYNCHRONIZING WITH AEGIS...</Text>
        </View>
      )}

      {/* Error State */}
      {error && (
        <View style={styles.errorContainer}>
          <Text style={styles.errorIcon}>🚨</Text>
          <Text style={styles.errorTitle}>CONNECTION SEVERED</Text>
          <Text style={styles.errorMsg}>The Secure Portal is unreachable. Check your uplink.</Text>
          <TouchableOpacity style={styles.retryBtn} onPress={handleReload}>
            <Text style={styles.retryText}>RE-ESTABLISH CONNECTION</Text>
          </TouchableOpacity>
        </View>
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#080D24',
  },
  webview: {
    flex: 1,
    backgroundColor: '#080D24',
  },
  overlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: '#080D24',
    justifyContent: 'center',
    alignItems: 'center',
    zIndex: 10,
  },
  loadingText: {
    color: '#94FBAB',
    marginTop: 20,
    fontSize: 10,
    letterSpacing: 2,
    fontWeight: '700',
  },
  errorContainer: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: '#080D24',
    justifyContent: 'center',
    alignItems: 'center',
    padding: 40,
    zIndex: 20,
  },
  errorIcon: {
    fontSize: 50,
    marginBottom: 20,
  },
  errorTitle: {
    color: '#FF6B6B',
    fontSize: 20,
    fontWeight: '800',
    marginBottom: 10,
  },
  errorMsg: {
    color: '#A0AEC0',
    textAlign: 'center',
    marginBottom: 30,
    lineHeight: 22,
  },
  retryBtn: {
    backgroundColor: '#94FBAB',
    paddingVertical: 15,
    paddingHorizontal: 30,
    borderRadius: 8,
  },
  retryText: {
    color: '#080D24',
    fontWeight: '800',
    fontSize: 12,
  }
});
