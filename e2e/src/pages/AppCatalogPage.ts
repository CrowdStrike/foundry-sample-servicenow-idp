/**
 * AppCatalogPage - App installation and management
 */

import { Page } from '@playwright/test';
import { BasePage } from './BasePage';
import { RetryHandler } from '../utils/SmartWaiter';
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

    await this.navigateToPath('/foundry/app-catalog', 'App catalog page');

    const filterBox = this.page.getByPlaceholder('Type to filter');
    await filterBox.fill(appName);
    await this.page.waitForLoadState('networkidle');

    const appLink = this.page.getByRole('link', { name: appName, exact: true });

    try {
      await this.waiter.waitForVisible(appLink, {
        description: `App '${appName}' link in catalog`,
        timeout: 10000
      });
      this.logger.success(`Found app '${appName}' in catalog`);
      await this.smartClick(appLink, `App '${appName}' link`);
      await this.page.waitForLoadState('networkidle');
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
    await this.page.waitForLoadState('networkidle');

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
   * Get field context by looking at nearby labels and text
   */
  private async getFieldContext(input: any): Promise<string> {
    try {
      // Try to find the label element
      const id = await input.getAttribute('id');
      if (id) {
        const label = this.page.locator(`label[for="${id}"]`);
        if (await label.isVisible({ timeout: 1000 }).catch(() => false)) {
          const labelText = await label.textContent();
          if (labelText) return labelText.toLowerCase();
        }
      }

      // Look at parent container for context
      const parent = input.locator('xpath=ancestor::div[contains(@class, "form") or contains(@class, "field") or contains(@class, "input")][1]');
      if (await parent.isVisible({ timeout: 1000 }).catch(() => false)) {
        const parentText = await parent.textContent();
        if (parentText) return parentText.toLowerCase();
      }
    } catch (error) {
      // Continue if we can't get context
    }
    return '';
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
   */
  private async configureApiIntegrationIfNeeded(): Promise<void> {
    let configCount = 0;
    let hasNextSetting = true;

    // Keep filling configs until we can't find either "Next setting" or more empty fields
    while (hasNextSetting) {
      configCount++;
      this.logger.info(`Configuration screen ${configCount} detected, filling fields...`);

      // Fill visible text inputs
      const inputs = this.page.locator('input[type="text"], input[type="url"], input:not([type="password"]):not([type])');
      const count = await inputs.count();
      this.logger.info(`Found ${count} text input fields`);

      for (let i = 0; i < count; i++) {
        const input = inputs.nth(i);
        if (await input.isVisible()) {
          const name = await input.getAttribute('name') || '';
          const placeholder = await input.getAttribute('placeholder') || '';
          const context = (await this.getFieldContext(input)).trim().replace(/\s+/g, ' ');

          const value = this.getFieldValue(context, name, placeholder, 'text');
          await input.fill(value);
          this.logger.info(`Filled input [${name || 'unnamed'}] context:"${context}" -> "${value}"`);
        }
      }

      // Fill password inputs
      const passwordInputs = this.page.locator('input[type="password"]');
      const passwordCount = await passwordInputs.count();
      this.logger.info(`Found ${passwordCount} password input fields`);

      for (let i = 0; i < passwordCount; i++) {
        const input = passwordInputs.nth(i);
        if (await input.isVisible()) {
          const name = await input.getAttribute('name') || '';
          const placeholder = await input.getAttribute('placeholder') || '';
          const context = (await this.getFieldContext(input)).trim().replace(/\s+/g, ' ');

          const value = this.getFieldValue(context, name, placeholder, 'password');
          await input.fill(value);
          this.logger.info(`Filled password [${name || 'unnamed'}] context:"${context}"`);
        }
      }

      // Fill select/dropdown fields (including Foundry custom dropdowns)
      // Foundry uses button-based dropdowns with aria-haspopup
      const selectFields = this.page.locator('select, [role="combobox"], button[aria-haspopup="listbox"], button[aria-haspopup="menu"]');
      const selectCount = await selectFields.count();
      this.logger.info(`Found ${selectCount} select/dropdown fields`);

      for (let i = 0; i < selectCount; i++) {
        const select = selectFields.nth(i);
        if (await select.isVisible()) {
          const name = await select.getAttribute('name') || '';
          const ariaLabel = await select.getAttribute('aria-label') || '';
          const tagName = await select.evaluate(el => el.tagName.toLowerCase());

          if (tagName === 'select') {
            // Native select element - select first non-empty option
            const options = select.locator('option');
            const optionCount = await options.count();

            if (optionCount > 1) {
              // Get the second option (first is usually empty/placeholder)
              const firstValue = await options.nth(1).getAttribute('value');
              if (firstValue) {
                await select.selectOption(firstValue);
                this.logger.info(`Selected option in select [${name || ariaLabel || 'unnamed'}]`);
              }
            }
          } else if (tagName === 'button') {
            // Foundry button-based dropdown - click button and select first option
            try {
              await select.click();
              await this.waiter.delay(1000);

              // Look for menu/listbox options
              const option = this.page.locator('[role="option"], [role="menuitem"]').first();
              if (await option.isVisible({ timeout: 2000 })) {
                await option.click();
                this.logger.info(`Selected option in button dropdown [${name || ariaLabel || 'unnamed'}]`);
                await this.waiter.delay(500);
              }
            } catch (error) {
              this.logger.info(`Could not select option in button dropdown [${name || ariaLabel || 'unnamed'}]: ${error.message}`);
            }
          } else {
            // Role="combobox" - click and select first option
            try {
              await select.click();
              await this.waiter.delay(500);

              // Look for listbox options
              const option = this.page.locator('[role="option"]').first();
              if (await option.isVisible({ timeout: 2000 })) {
                await option.click();
                this.logger.info(`Selected option in combobox [${name || ariaLabel || 'unnamed'}]`);
              }
            } catch (error) {
              this.logger.info(`Could not select option in combobox [${name || ariaLabel || 'unnamed'}]: ${error.message}`);
            }
          }
        }
      }

      // Check for "Next setting" button
      const nextSettingButton = this.page.getByRole('button', { name: /next setting/i });
      hasNextSetting = await this.elementExists(nextSettingButton, 2000);

      if (hasNextSetting) {
        this.logger.info(`Filled configuration screen ${configCount}, clicking Next setting`);
        await this.smartClick(nextSettingButton, 'Next setting button');
        await this.page.waitForLoadState('networkidle');
        await this.waiter.delay(3000);
      } else {
        this.logger.info(`No more "Next setting" button found after ${configCount} screen(s)`);
        break;
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
    await installButton.waitFor({ state: 'visible', timeout: 10000 });
    await installButton.waitFor({ state: 'attached', timeout: 5000 });

    // Simple delay for form to enable button
    await this.waiter.delay(1000);

    await this.smartClick(installButton, 'Install button');
    this.logger.info('Clicked Save and install button');
  }

  /**
   * Wait for installation to complete
   */
  private async waitForInstallation(appName: string): Promise<void> {
    this.logger.info('Waiting for installation to complete...');

    // Wait for URL to change or network to settle
    await Promise.race([
      this.page.waitForURL(/\/foundry\/(app-catalog|home)/, { timeout: 15000 }),
      this.page.waitForLoadState('networkidle', { timeout: 15000 })
    ]).catch(() => {});

    // Look for first "installing" message
    const installingMessage = this.page.getByText(/installing/i).first();

    try {
      await installingMessage.waitFor({ state: 'visible', timeout: 30000 });
      this.logger.success('Installation started - "installing" message appeared');
    } catch (error) {
      throw new Error(`Installation failed to start for app '${appName}' - "installing" message never appeared. Installation may have failed immediately.`);
    }

    // Wait for second toast with final status (installed or error)
    // Match exact toast messages using app name
    const installedMessage = this.page.getByText(`${appName} installed`).first();
    const errorMessage = this.page.getByText(`Error installing ${appName}`).first();

    try {
      const result = await Promise.race([
        installedMessage.waitFor({ state: 'visible', timeout: 60000 }).then(() => 'success'),
        errorMessage.waitFor({ state: 'visible', timeout: 60000 }).then(() => 'error')
      ]);

      if (result === 'error') {
        // Get the actual error message from the toast and clean up formatting
        const errorText = await errorMessage.textContent();
        const cleanError = errorText?.replace(/\s+/g, ' ').trim() || 'Unknown error';
        throw new Error(`Installation failed for app '${appName}': ${cleanError}`);
      }
      this.logger.success('Installation completed successfully - "installed" message appeared');
    } catch (error) {
      if (error.message.includes('Installation failed')) {
        throw error;
      }
      throw new Error(`Installation status unclear for app '${appName}' - timed out waiting for "installed" or "error" message after 60 seconds`);
    }
    // Brief catalog status check (5-10s) - "installed" toast is the real signal
    // This is just for logging/verification, not a hard requirement
    this.logger.info('Checking catalog status briefly (installation already confirmed by toast)...');

    // Navigate directly to app catalog with search query
    const baseUrl = new URL(this.page.url()).origin;
    await this.page.goto(`${baseUrl}/foundry/app-catalog?q=${appName}`);
    await this.page.waitForLoadState('networkidle');

    // Check status a couple times (up to 10 seconds)
    const statusText = this.page.locator('[data-test-selector="status-text"]').filter({ hasText: /installed/i });
    const maxAttempts = 2; // 2 attempts = up to 10 seconds

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const isVisible = await statusText.isVisible().catch(() => false);

      if (isVisible) {
        this.logger.success('Catalog status verified - shows Installed');
        return;
      }

      if (attempt < maxAttempts - 1) {
        this.logger.info(`Catalog status not yet updated, waiting 5s before refresh (attempt ${attempt + 1}/${maxAttempts})...`);
        await this.waiter.delay(5000);
        await this.page.reload({ waitUntil: 'domcontentloaded' });
      }
    }

    // Don't fail - the "installed" toast is reliable enough
    this.logger.info(`Catalog status not updated yet after ${maxAttempts * 5}s, but toast confirmed installation - continuing`);
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
