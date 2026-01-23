import { test, expect } from '../src/fixtures';

test.describe.configure({ mode: 'serial' });

test.describe('ServiceNow IDP - E2E Tests', () => {
  test('should verify ServiceNow API integration action is available in workflow builder', async ({ workflowsPage }) => {
    // This app requires ServiceNow API credentials which we don't have in E2E tests
    // We disable workflow provisioning on install to avoid credential validation
    // Instead, we verify the API integration action is available in the workflow builder
    test.setTimeout(90000); // 90 seconds
    await workflowsPage.navigateToWorkflows();
    await workflowsPage.createNewWorkflow();

    // Select "On demand" trigger
    const onDemandTrigger = workflowsPage.page.getByText('On demand').first();
    await onDemandTrigger.click();

    const nextButton = workflowsPage.page.getByRole('button', { name: 'Next' });
    await nextButton.click();

    await workflowsPage.page.waitForLoadState('networkidle');
    await workflowsPage.page.getByText('Add next').waitFor({ state: 'visible', timeout: 10000 });

    // Click "Add action" button to open action selection dialog
    const addNextMenu = workflowsPage.page.getByTestId('add-next-menu-container');
    const addActionButton = addNextMenu.getByTestId('context-menu-seq-action-button');
    await addActionButton.click();
    await workflowsPage.page.waitForLoadState('networkidle');

    // Wait for search box to be visible
    const searchBox = workflowsPage.page.getByRole('searchbox').or(workflowsPage.page.getByPlaceholder(/search/i));
    await searchBox.waitFor({ state: 'visible', timeout: 10000 });

    // Wait for initial action list loading to complete
    const loadingMessages = workflowsPage.page.getByText('This may take a few moments');
    await loadingMessages.first().waitFor({ state: 'hidden', timeout: 60000 }).catch(() => {});
    await workflowsPage.page.waitForLoadState('networkidle');

    // Search for the ServiceNow API integration action
    const actionName = 'service now cmdb table api';
    await expect(searchBox).toBeEnabled({ timeout: 10000 });
    await searchBox.fill(actionName);

    // Wait for search results to load
    await loadingMessages.first().waitFor({ state: 'hidden', timeout: 60000 }).catch(() => {});
    await workflowsPage.page.waitForLoadState('networkidle');

    // Expand "Other (Custom, Foundry, etc.)" section if it exists
    const otherSection = workflowsPage.page.getByText('Other (Custom, Foundry, etc.)');
    if (await otherSection.isVisible({ timeout: 2000 }).catch(() => false)) {
      await otherSection.click();

      // Wait for section's internal loading to complete
      await loadingMessages.first().waitFor({ state: 'hidden', timeout: 60000 }).catch(() => {});
      await workflowsPage.page.waitForLoadState('networkidle');
    }

    // Find all instances of this action (may include stale ones from previous installs)
    const actionElements = await workflowsPage.page.getByText(actionName, { exact: false }).all();

    if (actionElements.length === 0) {
      throw new Error(`Action '${actionName}' not found in search results`);
    }

    console.log(`Found ${actionElements.length} instance(s) of '${actionName}' - trying each until one works...`);

    let actionVerified = false;

    // Try each instance until we find one that's not stale
    for (let i = 0; i < actionElements.length; i++) {
      console.log(`  Trying instance ${i + 1}/${actionElements.length}...`);

      try {
        // Click on the action
        await actionElements[i].click();
        await workflowsPage.page.waitForLoadState('networkidle');

        // Wait for the details panel to load and check if configuration is present
        // Stale actions won't show the "Configure" heading
        try {
          const configureTab = workflowsPage.page.getByRole('tab', { name: 'Configure' });
          await configureTab.waitFor({ state: 'visible', timeout: 10000 });
          console.log(`✓ Action verified: ${actionName} - Configure section is present`);
          actionVerified = true;
          break;
        } catch (error) {
          const errorMsg = error.message || 'Unknown error';
          console.log(`  Instance ${i + 1} failed: ${errorMsg}`);
        }
      } catch (error) {
        console.log(`  Instance ${i + 1} failed: ${error.message}, trying next...`);
      }
    }

    if (!actionVerified) {
      throw new Error(`Failed to verify action '${actionName}' - all ${actionElements.length} instance(s) appear to be stale or invalid`);
    }

    console.log('ServiceNow API integration verified successfully');
  });
});
