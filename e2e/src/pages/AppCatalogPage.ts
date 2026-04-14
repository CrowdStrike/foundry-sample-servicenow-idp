/**
 * AppCatalogPage - App installation and management
 */

import { Page } from '@playwright/test';
import { BasePage } from './BasePage';
import { config } from '../config/TestConfig';

export class AppCatalogPage extends BasePage {
  constructor(page: Page) {
    super(page, 'AppCatalogPage');
  }

  protected getPagePath(): string {
    return '/foundry/app-catalog';
  }

  protected async verifyPageLoaded(): Promise<void> {
    await this.waiter.waitForVisible(
      this.page.locator('text=App Catalog').or(this.page.locator('text=Apps')),
      { description: 'App Catalog page' }
    );

    this.logger.success('App Catalog page loaded successfully');
  }

  /**
   * Search for app in catalog and navigate to its page
   */
  private async searchAndNavigateToApp(appName: string): Promise<void> {
    this.logger.info(`Searching for app '${appName}' in catalog`);

    // Navigate to app catalog with filter query parameter
    // Format: filter=name:~'searchterm'
    const baseUrl = config.falconBaseUrl || 'https://falcon.us-2.crowdstrike.com';
    const filterParam = encodeURIComponent(`name:~'${appName}'`);
    await this.page.goto(`${baseUrl}/foundry/app-catalog?filter=${filterParam}`);
    await this.page.waitForLoadState('domcontentloaded');

    const appLink = this.page.getByRole('link', { name: appName, exact: true });

    try {
      await this.waiter.waitForVisible(appLink, {
        description: `App '${appName}' link in catalog`,
        timeout: 10000
      });
      this.logger.success(`Found app '${appName}' in catalog`);
      await this.smartClick(appLink, `App '${appName}' link`);
      await this.page.waitForLoadState('domcontentloaded');
    } catch (error) {
      throw new Error(`Could not find app '${appName}' in catalog. Make sure the app is deployed.`);
    }
  }

  /**
   * Check if app is installed
   */
  async isAppInstalled(appName: string): Promise<boolean> {
    this.logger.step(`Check if app '${appName}' is installed`);

    // Search for and navigate to the app's catalog page
    await this.searchAndNavigateToApp(appName);

    // Check for installation indicators on the app's page
    // Simple check: if "Install now" link exists, app is NOT installed
    const installLink = this.page.getByRole('link', { name: 'Install now' });
    const hasInstallLink = await this.elementExists(installLink, 3000);

    const isInstalled = !hasInstallLink;
    this.logger.info(`App '${appName}' installation status: ${isInstalled ? 'Installed' : 'Not installed'}`);

    return isInstalled;
  }

  /**
   * Install app if not already installed
   */
  async installApp(appName: string): Promise<boolean> {
    this.logger.step(`Install app '${appName}'`);

    const isInstalled = await this.isAppInstalled(appName);
    if (isInstalled) {
      this.logger.info(`App '${appName}' is already installed`);
      return false;
    }

    // Click Install now link
    this.logger.info('App not installed, looking for Install now link');
    const installLink = this.page.getByRole('link', { name: 'Install now' });

    await this.waiter.waitForVisible(installLink, { description: 'Install now link' });
    await this.smartClick(installLink, 'Install now link');
    this.logger.info('Clicked Install now, waiting for install page to load');

    // Wait for URL to change to install page and page to stabilize
    await this.page.waitForURL(/\/foundry\/app-catalog\/[^\/]+\/install$/, { timeout: 10000 });
    await this.page.waitForLoadState('domcontentloaded');

    // Handle permissions dialog
    await this.handlePermissionsDialog();

    // Check for ServiceNow configuration screen
    await this.configureApiIntegrationIfNeeded();

    // Click final Install app button
    await this.clickInstallAppButton();

    // Wait for installation to complete
    await this.waitForInstallation(appName);

    this.logger.success(`App '${appName}' installed successfully`);
    return true;
  }

  /**
   * Handle permissions dialog if present
   */
  private async handlePermissionsDialog(): Promise<void> {
    const acceptButton = this.page.getByRole('button', { name: /accept.*continue/i });

    if (await this.elementExists(acceptButton, 3000)) {
      this.logger.info('Permissions dialog detected, accepting');
      await this.smartClick(acceptButton, 'Accept and continue button');
      await this.waiter.delay(2000);
    }
  }

  /**
   * Click a dropdown button and select the first available option
   */
  private async selectFirstDropdownOption(button: any, label: string): Promise<void> {
    try {
      await button.click();
      await this.waiter.delay(1000);

      const option = this.page.locator('[role="option"], [role="menuitem"]').first();
      if (await option.isVisible({ timeout: 3000 })) {
        await option.click();
        this.logger.info(`Selected option in dropdown [${label}]`);
        await this.waiter.delay(500);
      }
    } catch (error) {
      this.logger.info(`Could not select option in dropdown [${label}]: ${error.message}`);
    }
  }

  /**
   * Get value for a field based on its context
   */
  private getFieldValue(context: string, name: string, placeholder: string, inputType: string): string {
    const combined = `${context} ${name} ${placeholder}`.toLowerCase();

    // ServiceNow-specific field detection
    if (combined.includes('host') || combined.includes('url')) {
      return 'https://example.com';
    }

    if (combined.includes('name') && !combined.includes('host') && !combined.includes('user')) {
      return 'ServiceNow Test Instance';
    }

    if (combined.includes('username') || combined.includes('user')) {
      return 'foundry_test_user';
    }

    if (inputType === 'password') {
      return 'test-password';
    }

    // Default values
    return 'test-value';
  }

  /**
   * Configure API integration if configuration form is present during installation.
   * Fills in dummy values for all configuration fields and clicks through multiple settings.
   *
   * The install flow has two settings screens:
   *   1. Setting 1 (workflow config): text fields + Recipients combobox + "How often" dropdown
   *   2. service now cmdb (API credentials): Name, Host, Username, Password
   */
  private async configureApiIntegrationIfNeeded(): Promise<void> {
    let configCount = 0;
    let hasMoreSettings = true;

    while (hasMoreSettings) {
      configCount++;
      this.logger.info(`Configuration screen ${configCount} detected, filling fields...`);

      // Fill all visible textbox fields (Foundry renders both text and password as role="textbox")
      const textboxes = this.page.getByRole('textbox');
      const textboxCount = await textboxes.count();
      this.logger.info(`Found ${textboxCount} textbox fields`);

      for (let i = 0; i < textboxCount; i++) {
        const input = textboxes.nth(i);
        if (await input.isVisible()) {
          const name = await input.getAttribute('name') || '';
          const ariaLabel = await input.evaluate(el => el.getAttribute('aria-label') || '');
          const currentValue = await input.inputValue().catch(() => '');

          // Skip fields that already have values (e.g., Start time "00:00")
          if (currentValue) continue;

          // Skip search fields
          if (ariaLabel.toLowerCase().includes('search')) continue;

          const context = `${ariaLabel} ${name}`.toLowerCase();
          const value = this.getFieldValue(context, name, '', ariaLabel.toLowerCase().includes('password') ? 'password' : 'text');
          await input.fill(value);
          this.logger.info(`Filled textbox [${ariaLabel || name || 'unnamed'}] -> "${ariaLabel.toLowerCase().includes('password') ? '***' : value}"`);
        }
      }

      // Fill combobox fields (e.g., Recipients) by typing a value and pressing Enter
      const comboboxes = this.page.getByRole('combobox');
      const comboboxCount = await comboboxes.count();
      this.logger.info(`Found ${comboboxCount} combobox fields`);

      for (let i = 0; i < comboboxCount; i++) {
        const combobox = comboboxes.nth(i);
        if (await combobox.isVisible()) {
          const ariaLabel = await combobox.evaluate(el => el.getAttribute('aria-label') || '');
          // Check if the combobox already has selected values
          const selectedContainer = combobox.locator('xpath=ancestor::*[1]').locator('text=Selected:');
          const hasSelection = await selectedContainer.isVisible({ timeout: 500 }).catch(() => false);

          if (!hasSelection) {
            await combobox.fill('test@example.com');
            await combobox.press('Enter');
            this.logger.info(`Filled combobox [${ariaLabel || 'unnamed'}] with "test@example.com" + Enter`);
            await this.waiter.delay(500);
          } else {
            this.logger.info(`Combobox [${ariaLabel || 'unnamed'}] already has a selection, skipping`);
          }
        }
      }

      // Handle "How often" dropdown - now shows "Select interval" by default
      const howOftenBtn = this.page.getByRole('button', { name: /how often.*select interval/i });
      if (await howOftenBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
        this.logger.info('Found "How often" dropdown with "Select interval", selecting Hourly...');
        await this.selectFirstDropdownOption(howOftenBtn, 'How often');
        await this.waiter.delay(1000);
      }

      // Handle any remaining dropdowns with "Select" placeholder
      const allButtons = this.page.locator('button');
      const buttonCount = await allButtons.count();
      for (let i = 0; i < buttonCount; i++) {
        const btn = allButtons.nth(i);
        if (await btn.isVisible()) {
          const btnText = (await btn.textContent() || '').trim();
          if (/select\s/i.test(btnText) && !btnText.includes('Select interval')) {
            this.logger.info(`Found unselected dropdown: "${btnText}"`);
            await this.selectFirstDropdownOption(btn, btnText);
          }
        }
      }

      // Determine next action: "Next setting" or "Install app"
      const nextSettingButton = this.page.getByRole('button', { name: /next setting/i });
      const installButton = this.page.getByRole('button', { name: 'Install app' })
        .or(this.page.getByRole('button', { name: 'Save and install' }));

      const hasNextSetting = await this.elementExists(nextSettingButton, 2000);
      const hasInstallButton = await this.elementExists(installButton, 1000);

      if (hasNextSetting && !hasInstallButton) {
        this.logger.info(`Filled configuration screen ${configCount}, clicking Next setting`);
        await this.smartClick(nextSettingButton, 'Next setting button');
        await this.page.waitForLoadState('domcontentloaded');
        await this.waiter.delay(3000);
      } else {
        this.logger.info(`Configuration complete after ${configCount} screen(s)`);
        hasMoreSettings = false;
      }
    }

    this.logger.info(`Completed ${configCount} configuration screen(s)`);
  }

  /**
   * Click the final "Save and install" button
   */
  private async clickInstallAppButton(): Promise<void> {
    const installButton = this.page.getByRole('button', { name: 'Save and install' })
      .or(this.page.getByRole('button', { name: 'Install app' }));

    await this.waiter.waitForVisible(installButton, { description: 'Install button' });

    // Wait for button to be enabled
    await installButton.waitFor({ state: 'visible', timeout: 30000 });
    await installButton.waitFor({ state: 'attached', timeout: 5000 });

    // Wait for button to be enabled (CI is slower to validate form fields)
    const delay = config.isCI ? 5000 : 3000;
    await this.waiter.delay(delay);

    // Verify button is not disabled before clicking
    const isDisabled = await installButton.isDisabled().catch(() => false);
    if (isDisabled) {
      this.logger.info('Install button is disabled, waiting for it to become enabled...');
      await installButton.waitFor({ state: 'visible', timeout: 15000 });
      await this.waiter.delay(3000);
    }

    await this.smartClick(installButton, 'Install button');
    this.logger.info('Clicked Save and install button');
  }

  /**
   * Wait for installation to complete
   */
  private async waitForInstallation(appName: string): Promise<void> {
    this.logger.info('Waiting for installation to complete...');

    // Wait for all possible outcomes simultaneously - don't block on URL/networkidle
    // first since the "installing" toast could appear and disappear during that window.
    const installingMessage = this.page.getByText(/installing/i).first();
    const installedMessage = this.page.getByText(`${appName} installed`).first();
    const errorMessage = this.page.getByText(`Error installing ${appName}`).first();

    try {
      const result = await Promise.race([
        installingMessage.waitFor({ state: 'visible', timeout: 120000 }).then(() => 'installing'),
        installedMessage.waitFor({ state: 'visible', timeout: 120000 }).then(() => 'installed'),
        errorMessage.waitFor({ state: 'visible', timeout: 120000 }).then(() => 'error')
      ]);

      if (result === 'error') {
        const errorText = await errorMessage.textContent();
        const cleanError = errorText?.replace(/\s+/g, ' ').trim() || 'Unknown error';
        throw new Error(`Installation failed for app '${appName}': ${cleanError}`);
      }

      if (result === 'installing') {
        this.logger.success('Installation started - "installing" message appeared');

        // Now wait for final status
        try {
          const finalResult = await Promise.race([
            installedMessage.waitFor({ state: 'visible', timeout: 120000 }).then(() => 'success'),
            errorMessage.waitFor({ state: 'visible', timeout: 120000 }).then(() => 'error')
          ]);

          if (finalResult === 'error') {
            const errorText = await errorMessage.textContent();
            const cleanError = errorText?.replace(/\s+/g, ' ').trim() || 'Unknown error';
            throw new Error(`Installation failed for app '${appName}': ${cleanError}`);
          }
        } catch (error) {
          if (error.message.includes('Installation failed')) throw error;
          throw new Error(`Installation status unclear for app '${appName}' - timed out waiting for final status`);
        }
      }

      this.logger.success('Installation completed successfully');
    } catch (error) {
      if (error.message.includes('Installation failed') || error.message.includes('Installation status unclear')) {
        throw error;
      }

      // Take a screenshot to help debug CI failures
      await this.page.screenshot({ path: `test-results/install-timeout-${Date.now()}.png`, fullPage: true }).catch(() => {});
      const currentUrl = this.page.url();
      throw new Error(`Installation failed to start for app '${appName}' - no install messages appeared within 120s. Current URL: ${currentUrl}`);
    }

    // Brief catalog status check - toast is the real signal
    this.logger.info('Checking catalog status briefly...');
    const baseUrl = new URL(this.page.url()).origin;
    await this.page.goto(`${baseUrl}/foundry/app-catalog?filter=name%3A~%27${appName}%27`);
    await this.page.waitForLoadState('domcontentloaded');

    const statusText = this.page.locator('[data-test-selector="status-text"]').filter({ hasText: /installed/i });
    for (let attempt = 0; attempt < 2; attempt++) {
      if (await statusText.isVisible().catch(() => false)) {
        this.logger.success('Catalog status verified - shows Installed');
        return;
      }
      if (attempt < 1) {
        await this.waiter.delay(5000);
        await this.page.reload({ waitUntil: 'domcontentloaded' });
      }
    }

    this.logger.info('Catalog status not yet updated, but toast confirmed installation - continuing');
  }

  /**
   * Uninstall app
   */
  async uninstallApp(appName: string): Promise<void> {
    this.logger.step(`Uninstall app '${appName}'`);

    try {
      // Search for and navigate to the app's catalog page
      await this.searchAndNavigateToApp(appName);

      // Check if app is actually installed by looking for "Install now" link
      // If "Install now" link exists, app is NOT installed
      const installLink = this.page.getByRole('link', { name: 'Install now' });
      const hasInstallLink = await this.elementExists(installLink, 3000);

      if (hasInstallLink) {
        this.logger.info(`App '${appName}' is already uninstalled`);
        return;
      }

      // Click the 3-dot menu button
      const openMenuButton = this.page.getByRole('button', { name: 'Open menu' });
      await this.waiter.waitForVisible(openMenuButton, { description: 'Open menu button' });
      await this.smartClick(openMenuButton, 'Open menu button');

      // Click "Uninstall app" menuitem
      const uninstallMenuItem = this.page.getByRole('menuitem', { name: 'Uninstall app' });
      await this.waiter.waitForVisible(uninstallMenuItem, { description: 'Uninstall app menuitem' });
      await this.smartClick(uninstallMenuItem, 'Uninstall app menuitem');

      // Confirm uninstallation in modal
      const uninstallButton = this.page.getByRole('button', { name: 'Uninstall' });
      await this.waiter.waitForVisible(uninstallButton, { description: 'Uninstall confirmation button' });
      await this.smartClick(uninstallButton, 'Uninstall button');

      // Wait for success message (toast notification)
      // Wait up to 60 seconds for the uninstalled toast to appear
      const successMessage = this.page.getByText(/has been uninstalled|uninstalled successfully/i);
      await this.waiter.waitForVisible(successMessage, {
        description: 'Uninstall success message',
        timeout: 60000
      });

      this.logger.success(`App '${appName}' uninstalled successfully`);

    } catch (error) {
      this.logger.warn(`Failed to uninstall app '${appName}': ${error.message}`);
      throw error;
    }
  }
}
