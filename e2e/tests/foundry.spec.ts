import { test, expect } from '../src/fixtures';

test.describe.configure({ mode: 'serial' });

test.describe('ServiceNow IDP - E2E Tests', () => {
  test('should verify ServiceNow API integration action is available in workflow builder', async ({ workflowsPage }) => {
    // This app requires ServiceNow API credentials which we don't have in E2E tests
    // We disable workflow provisioning on install to avoid credential validation
    // Instead, we verify the API integration action is available in the workflow builder
    await workflowsPage.navigateToWorkflows();
    await workflowsPage.createNewWorkflow();

    // Select "On demand" trigger
    const onDemandTrigger = workflowsPage.page.getByText('On demand').first();
    await onDemandTrigger.click();

    const nextButton = workflowsPage.page.getByRole('button', { name: 'Next' });
    await nextButton.click();

    await workflowsPage.page.waitForLoadState('networkidle');
    await workflowsPage.page.getByText('Add next').waitFor({ state: 'visible', timeout: 10000 });

    // Click "Add action" button
    const addNextMenu = workflowsPage.page.getByTestId('add-next-menu-container');
    const addActionButton = addNextMenu.getByTestId('context-menu-seq-action-button');
    await addActionButton.click();

    await workflowsPage.page.waitForLoadState('networkidle');

    // Search for the ServiceNow API integration action
    const searchBox = workflowsPage.page.getByRole('searchbox').or(workflowsPage.page.getByPlaceholder(/search/i));
    await searchBox.fill('service now cmdb table api');

    await workflowsPage.page.getByText('This may take a few moments').waitFor({ state: 'hidden', timeout: 30000 });
    await workflowsPage.page.waitForLoadState('networkidle');

    // Verify the action is visible
    const actionElement = workflowsPage.page.getByText('service now cmdb table api', { exact: false });
    await expect(actionElement).toBeVisible({ timeout: 10000 });
    console.log('✓ API integration action available: service now cmdb table api');

    console.log('ServiceNow API integration verified successfully');
  });
});
