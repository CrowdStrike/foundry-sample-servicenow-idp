import { test as setup } from '@playwright/test';
import { AppCatalogPage, config } from '@crowdstrike/foundry-playwright';

setup('install app', async ({ page }) => {
  setup.setTimeout(180000);
  const catalog = new AppCatalogPage(page);

  await catalog.installApp(config.appName, {
    configureSettings: async (page) => {
      // Setting 1: Workflow configuration fields
      await page.getByLabel('CmdbAppNameColumn').fill('name');
      await page.getByLabel('HostGuidColumn').fill('host_guid');
      await page.getByLabel('HostRetiredColumn').fill('u_host_retired');
      await page.getByLabel('IdpActionColumn').fill('u_idp_action');
      await page.getByLabel('IdpEnabledColumn').fill('u_idp_enabled');
      await page.getByLabel('IdpRuleNamePrefix').fill('SN-');
      await page.getByLabel('IdpSimulationModeColumn').fill('u_idp_simulation');
      await page.getByLabel('IdpTriggerColumn').fill('u_idp_trigger');
      await page.getByLabel('SysUpdatedOnColumn').fill('sys_updated_on');
      await page.getByLabel('TableName').fill('cmdb_ci_server');
      await page.getByLabel('UserGuidColumn').fill('user_guid');
      await page.getByLabel('UserRetiredColumn').fill('u_user_retired');
      await page.getByLabel('SysParamLimit').fill('100');

      // Email recipient (combobox)
      const toCombobox = page.getByRole('combobox', { name: 'Recipients' });
      if (await toCombobox.isVisible({ timeout: 2000 }).catch(() => false)) {
        await toCombobox.click();
        await toCombobox.fill('test@example.com');
        await page.keyboard.press('Enter');
        await page.locator('body').click({ position: { x: 0, y: 0 } });
      }

      // "How often" timer/schedule dropdown
      const howOftenDropdown = page.getByLabel('How often').or(page.locator('button', { hasText: 'Select interval' }));
      await howOftenDropdown.click();
      const firstOption = page.locator('[role="option"]').first();
      await firstOption.waitFor({ state: 'visible', timeout: 5000 });
      await firstOption.click();

      // Navigate to Setting 2: ServiceNow API integration
      const nextButton = page.getByRole('button', { name: /next setting/i });
      await nextButton.click();
      await page.waitForLoadState('domcontentloaded').catch(() => {});

      // ServiceNow API integration (basic auth)
      await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ServiceNow Test Instance');
      await page.getByRole('textbox', { name: 'Host', exact: true }).fill(process.env.SERVICENOW_INSTANCE_URL || 'https://example.service-now.com');
      await page.getByRole('textbox', { name: 'Username' }).fill(process.env.SERVICENOW_USERNAME || 'foundry_test_user');
      await page.getByRole('textbox', { name: 'Password' }).fill(process.env.SERVICENOW_PASSWORD || 'test-password');
    },
  });
});
