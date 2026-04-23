import { test as baseTest } from '@playwright/test';
import { AppCatalogPage, WorkflowsPage, config } from '@crowdstrike/foundry-playwright';

type FoundryFixtures = {
  appCatalogPage: AppCatalogPage;
  workflowsPage: WorkflowsPage;
  appName: string;
};

export const test = baseTest.extend<FoundryFixtures>({
  appCatalogPage: async ({ page }, use) => {
    await use(new AppCatalogPage(page));
  },

  workflowsPage: async ({ page }, use) => {
    await use(new WorkflowsPage(page));
  },

  appName: async ({}, use) => {
    await use(config.appName);
  },
});

export { expect } from '@playwright/test';
