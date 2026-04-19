# 🛡️ Aegis Mobile: APK Build Guide

Follow these steps to convert your Aegis Portal into a native Android application (.apk).

## 🛠️ Prerequisites
1. **Node.js installed** on your computer.
2. An **Expo Account** (Sign up at [expo.dev](https://expo.dev/signup)).

## 🚀 Step 1: Install Build Tools
Open your terminal and run:
```bash
npm install -g expo-cli eas-cli
```

## 📂 Step 2: Navigate to Project
```bash
cd AegisMobile
```

## 🔑 Step 3: Login to Expo
```bash
eas login
```

## 🏗️ Step 4: Configure Project
Run this to initialize the build configuration:
```bash
eas build:configure
```
*Select **Android** when prompted.*

## 📦 Step 5: Build the APK
Run the following command to start the cloud build:
```bash
eas build -p android --profile preview
```
*This will take about 5–10 minutes. Expo will build the app on their servers and provide a download link at the end.*

## 📲 Step 6: Install & Share
1. Download the resulting `.apk` file.
2. Transfer it to your Realme phone.
3. Open the file to install (you may need to "Allow installation from unknown sources").
4. **Final Step**: Update the "Download APK" link in `main.py` with your new Expo link!

---
**Note:** To change the app icon, replace the files in `AegisMobile/assets/` before building.
