import { test, expect } from '../src/fixtures';

test.describe.configure({ mode: 'serial' });

test.describe('ServiceNow IDP - E2E Tests', () => {
  test('should verify ServiceNow API integration action is available in workflow builder', async ({ page, workflowsPage }) => {
    test.setTimeout(90000);
    await workflowsPage.navigateToWorkflows();
    await workflowsPage.createNewWorkflow();

    // Select "On demand" trigger
    const onDemandTrigger = page.getByText('On demand').first();
    await onDemandTrigger.click();

    const nextButton = page.getByRole('button', { name: 'Next' });
    await nextButton.click();

    await page.waitForLoadState('domcontentloaded');
    await page.getByText('Add next').waitFor({ state: 'visible', timeout: 10000 });

    // Click "Add action" button to open action selection dialog
    const addNextMenu = page.getByTestId('add-next-menu-container');
    const addActionButton = addNextMenu.getByTestId('context-menu-seq-action-button');
    await addActionButton.click();
    await page.waitForLoadState('domcontentloaded');

    // Wait for search box to be visible
    const searchBox = page.getByRole('searchbox').or(page.getByPlaceholder(/search/i));
    await searchBox.waitFor({ state: 'visible', timeout: 10000 });

    // Wait for initial action list loading to complete
    const loadingMessages = page.getByText('This may take a few moments');
    await loadingMessages.first().waitFor({ state: 'hidden', timeout: 60000 }).catch(() => {});
    await page.waitForLoadState('domcontentloaded');

    // Search for the ServiceNow API integration action
    const actionName = 'service now cmdb table api';
    await expect(searchBox).toBeEnabled({ timeout: 10000 });
    await searchBox.fill(actionName);

    // Wait for search results to load
    await loadingMessages.first().waitFor({ state: 'hidden', timeout: 60000 }).catch(() => {});
    await page.waitForLoadState('domcontentloaded');

    // Expand "Other (Custom, Foundry, etc.)" section if it exists
    const otherSection = page.getByText('Other (Custom, Foundry, etc.)');
    if (await otherSection.isVisible({ timeout: 2000 }).catch(() => false)) {
      await otherSection.click();

      await loadingMessages.first().waitFor({ state: 'hidden', timeout: 60000 }).catch(() => {});
      await page.waitForLoadState('domcontentloaded');
    }

    // Find all instances of this action (may include stale ones from previous installs)
    const actionElements = await page.getByText(actionName, { exact: false }).all();

    if (actionElements.length === 0) {
      throw new Error(`Action '${actionName}' not found in search results`);
    }

    console.log(`Found ${actionElements.length} instance(s) of '${actionName}' - trying each until one works...`);

    let actionVerified = false;

    for (let i = 0; i < actionElements.length; i++) {
      console.log(`  Trying instance ${i + 1}/${actionElements.length}...`);

      try {
        await actionElements[i].click();
        await page.waitForLoadState('domcontentloaded');

        try {
          const configureTab = page.getByRole('tab', { name: 'Configure' });
          const executionTab = page.getByRole('tab', { name: 'Execution settings' });
          await Promise.race([
            configureTab.waitFor({ state: 'visible', timeout: 10000 }),
            executionTab.waitFor({ state: 'visible', timeout: 10000 })
          ]);
          console.log(`Action verified: ${actionName} - action details panel is present`);
          actionVerified = true;
          break;
        } catch (error) {
          const errorMsg = (error as Error).message || 'Unknown error';
          console.log(`  Instance ${i + 1} failed: ${errorMsg}`);
        }
      } catch (error) {
        console.log(`  Instance ${i + 1} failed: ${(error as Error).message}, trying next...`);
      }
    }

    if (!actionVerified) {
      throw new Error(`Failed to verify action '${actionName}' - all ${actionElements.length} instance(s) appear to be stale or invalid`);
    }

    console.log('ServiceNow API integration verified successfully');
  });
});
