import { test as setup } from '../src/fixtures';

setup('install servicenow idp app', async ({ appCatalogPage, appName }) => {
  setup.setTimeout(180000); // 3 minutes for installation on slower CI runners
  // Check if app is already installed (this navigates to the app page)
  const isInstalled = await appCatalogPage.isAppInstalled(appName);

  if (!isInstalled) {
    console.log(`App '${appName}' is not installed. Installing...`);

    // Install the app
    const installed = await appCatalogPage.installApp(appName);

    if (!installed) {
      throw new Error(`Failed to install app '${appName}'`);
    }
  } else {
    console.log(`App '${appName}' is already installed`);
  }
});
