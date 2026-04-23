import { test as setup } from '@playwright/test';
import { AppCatalogPage, config } from '@crowdstrike/foundry-playwright';

setup('install app', async ({ page }) => {
  setup.setTimeout(180000);
  const catalog = new AppCatalogPage(page);

  await catalog.installApp(config.appName, {
    configureSettings: async (page) => {
      // Screen 1: ServiceNow API integration (basic auth, multi-instance)
      await page.getByLabel('Name').first().fill('ServiceNow Test Instance');
      await page.getByLabel('Host').fill('https://example.service-now.com');
      await page.getByLabel('Username').fill('foundry_test_user');
      await page.getByLabel('Password').fill('test-password');

      // Screen 2: Workflow configuration fields
      const nextButton = page.getByRole('button', { name: /next setting/i });
      await nextButton.click();
      await page.waitForLoadState('networkidle').catch(() => {});

      // Required workflow config fields from ServiceNow_to_IDP_policy_rules_synchronizer.yml
      await page.getByLabel('CmdbAppNameColumn').fill('name');
      await page.getByLabel('HostGuidColumn').fill('host_guid');
      await page.getByLabel('IdpActionColumn').fill('u_idp_action');
      await page.getByLabel('IdpEnabledColumn').fill('u_idp_enabled');
      await page.getByLabel('IdpRuleNamePrefix').fill('SN-');
      await page.getByLabel('IdpSimulationModeColumn').fill('u_idp_simulation');
      await page.getByLabel('IdpTriggerColumn').fill('u_idp_trigger');
      await page.getByLabel('SysUpdatedOnColumn').fill('sys_updated_on');
      await page.getByLabel('TableName').fill('cmdb_ci_server');
      await page.getByLabel('UserGuidColumn').fill('user_guid');

      // Optional fields
      const hostRetiredField = page.getByLabel('HostRetiredColumn');
      if (await hostRetiredField.isVisible({ timeout: 2000 }).catch(() => false)) {
        await hostRetiredField.fill('u_host_retired');
      }
      const userRetiredField = page.getByLabel('UserRetiredColumn');
      if (await userRetiredField.isVisible({ timeout: 2000 }).catch(() => false)) {
        await userRetiredField.fill('u_user_retired');
      }
      const sysParamLimitField = page.getByLabel('SysParamLimit');
      if (await sysParamLimitField.isVisible({ timeout: 2000 }).catch(() => false)) {
        await sysParamLimitField.fill('100');
      }

      // Email recipient (combobox)
      const toCombobox = page.getByRole('combobox');
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
    },
  });
});
