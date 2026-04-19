import React, { useRef, useState } from 'react';
import { StyleSheet, View, ActivityIndicator, StatusBar, BackHandler } from 'react-native';
import { WebView } from 'react-native-webview';

const AEGIS_URL = 'https://aegis-app-bakaywhetrffizyxtq7thm.streamlit.app/';

export default function App() {
  const webViewRef = useRef(null);
  const [loading, setLoading] = useState(true);
  const [canGoBack, setCanGoBack] = useState(false);

  // Android hardware back button support
  React.useEffect(() => {
    const onBackPress = () => {
      if (canGoBack && webViewRef.current) {
        webViewRef.current.goBack();
        return true;
      }
      return false;
    };
    BackHandler.addEventListener('hardwareBackPress', onBackPress);
    return () => BackHandler.removeEventListener('hardwareBackPress', onBackPress);
  }, [canGoBack]);

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#080D24" />
      
      {loading && (
        <View style={styles.loader}>
          <ActivityIndicator size="large" color="#7064DF" />
        </View>
      )}
      
      <WebView
        ref={webViewRef}
        source={{ uri: AEGIS_URL }}
        style={styles.webview}
        onLoadEnd={() => setLoading(false)}
        onNavigationStateChange={navState => setCanGoBack(navState.canGoBack)}
        // Inject CSS to hide Streamlit branding & optimize for mobile
        injectedJavaScript={`
          const style = document.createElement('style');
          style.textContent = \`
            #MainMenu, footer, .stDeployButton, [data-testid="stHeader"] { display: none !important; }
            @media (max-width: 768px) {
              .stButton > button { min-height: 48px; }
              input { font-size: 16px !important; }
            }
          \`;
          document.head.appendChild(style);
          true;
        `}
        javaScriptEnabled={true}
        domStorageEnabled={true}
        startInLoadingState={true}
        allowsBackForwardNavigationGestures={true}
        sharedCookiesEnabled={true}
        allowFileAccess={true}
        allowFileAccessFromFileURLs={true}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#080D24' },
  webview: { flex: 1 },
  loader: {
    position: 'absolute', top: 0, left: 0, right: 0, bottom: 0,
    justifyContent: 'center', alignItems: 'center',
    backgroundColor: '#080D24', zIndex: 10,
  },
});
