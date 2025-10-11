<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api';
	import { addNotification } from '$lib/stores';
	import type { Template, TemplateFilter, CreateTemplateRequest, UpdateTemplateRequest } from '$lib/types';

	let templates: Template[] = [];
	let loading = false;
	let showCreateModal = false;
	let showEditModal = false;
	let showPreviewModal = false;
	let selectedTemplate: Template | null = null;
	let filter: TemplateFilter = { limit: 20, offset: 0 };
	let total = 0;

	// Create/Edit form
	let templateForm: CreateTemplateRequest = {
		type: 'email',
		purpose: 'login',
		language: 'en',
		subject: '',
		content: '',
		is_default: false,
		is_active: true
	};

	// Preview
	let previewVariables: Record<string, any> = {};
	let previewResult = { rendered_content: '', rendered_subject: '' };
	let availableVariables: any[] = [];

	const templatePurposes = [
		{ value: 'login', label: 'Login' },
		{ value: 'registration', label: 'Registration' },
		{ value: 'verification', label: 'Verification' },
		{ value: 'password_reset', label: 'Password Reset' }
	];

	onMount(() => {
		loadTemplates();
	});

	async function loadTemplates() {
		loading = true;
		try {
			const response = await api.listTemplates(filter);
			templates = response.data?.data || [];
			total = response.data?.total || 0;
		} catch (error) {
			addNotification('error', 'Failed to load templates');
		} finally {
			loading = false;
		}
	}

	async function createTemplate() {
		try {
			await api.createTemplate(templateForm);
			addNotification('success', 'Template created successfully');
			showCreateModal = false;
			resetForm();
			loadTemplates();
		} catch (error) {
			addNotification('error', `Failed to create template: ${error}`);
		}
	}

	async function updateTemplate() {
		if (!selectedTemplate) return;

		try {
			const updateData: UpdateTemplateRequest = {
				subject: templateForm.subject,
				content: templateForm.content,
				is_active: templateForm.is_active
			};
			
			await api.updateTemplate(selectedTemplate.id, updateData);
			addNotification('success', 'Template updated successfully');
			showEditModal = false;
			resetForm();
			loadTemplates();
		} catch (error) {
			addNotification('error', `Failed to update template: ${error}`);
		}
	}

	async function deleteTemplate(template: Template) {
		if (!confirm(`Are you sure you want to delete the ${template.type} template for ${template.purpose}?`)) {
			return;
		}

		try {
			await api.deleteTemplate(template.id);
			addNotification('success', 'Template deleted successfully');
			loadTemplates();
		} catch (error) {
			addNotification('error', `Failed to delete template: ${error}`);
		}
	}

	async function openPreviewModal(template: Template) {
		selectedTemplate = template;
		
		try {
			// Load available variables for this purpose
			const variablesResponse = await api.getTemplateVariables(template.purpose);
			availableVariables = variablesResponse.data?.variables || [];
			
			// Initialize preview variables with example values
			previewVariables = {};
			availableVariables.forEach(variable => {
				previewVariables[variable.name] = variable.example || '';
			});
			
			// Generate initial preview
			await generatePreview();
			showPreviewModal = true;
		} catch (error) {
			addNotification('error', 'Failed to load template preview');
		}
	}

	async function generatePreview() {
		if (!selectedTemplate) return;

		try {
			const response = await api.previewTemplate(selectedTemplate.id, previewVariables);
			previewResult = response.data || { rendered_content: '', rendered_subject: '' };
		} catch (error) {
			addNotification('error', 'Failed to generate preview');
		}
	}

	function openCreateModal() {
		resetForm();
		showCreateModal = true;
	}

	function openEditModal(template: Template) {
		selectedTemplate = template;
		templateForm = {
			type: template.type,
			purpose: template.purpose,
			language: template.language,
			subject: template.subject || '',
			content: template.content,
			is_default: template.is_default,
			is_active: template.is_active
		};
		showEditModal = true;
	}

	function resetForm() {
		templateForm = {
			type: 'email',
			purpose: 'login',
			language: 'en',
			subject: '',
			content: '',
			is_default: false,
			is_active: true
		};
		selectedTemplate = null;
	}

	function formatDate(dateString: string) {
		return new Date(dateString).toLocaleDateString();
	}

	function getTypeBadge(type: string) {
		return type === 'email' 
			? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'
			: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200';
	}

	// Pagination
	function nextPage() {
		if (filter.offset + filter.limit < total) {
			filter.offset += filter.limit;
			loadTemplates();
		}
	}

	function prevPage() {
		if (filter.offset > 0) {
			filter.offset = Math.max(0, filter.offset - filter.limit);
			loadTemplates();
		}
	}
</script>

<svelte:head>
	<title>Template Management - Admin Dashboard</title>
</svelte:head>

<div class="space-y-6">
	<!-- Header -->
	<div class="flex justify-between items-center">
		<div>
			<h1 class="text-2xl font-bold text-gray-900 dark:text-white">Template Management</h1>
			<p class="text-gray-600 dark:text-gray-400">Manage email and SMS templates for authentication</p>
		</div>
		<button
			type="button"
			class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-medium"
			on:click={openCreateModal}
		>
			Create Template
		</button>
	</div>

	<!-- Filters -->
	<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
		<div class="grid grid-cols-1 md:grid-cols-4 gap-4">
			<div>
				<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
					Type
				</label>
				<select
					class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
					bind:value={filter.type}
					on:change={loadTemplates}
				>
					<option value="">All Types</option>
					<option value="email">Email</option>
					<option value="sms">SMS</option>
				</select>
			</div>
			<div>
				<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
					Purpose
				</label>
				<select
					class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
					bind:value={filter.purpose}
					on:change={loadTemplates}
				>
					<option value="">All Purposes</option>
					{#each templatePurposes as purpose}
						<option value={purpose.value}>{purpose.label}</option>
					{/each}
				</select>
			</div>
			<div>
				<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
					Language
				</label>
				<select
					class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
					bind:value={filter.language}
					on:change={loadTemplates}
				>
					<option value="">All Languages</option>
					<option value="en">English</option>
					<option value="es">Spanish</option>
					<option value="fr">French</option>
				</select>
			</div>
			<div>
				<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
					Status
				</label>
				<select
					class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
					bind:value={filter.is_active}
					on:change={loadTemplates}
				>
					<option value="">All</option>
					<option value={true}>Active</option>
					<option value={false}>Inactive</option>
				</select>
			</div>
		</div>
	</div>

	<!-- Templates table -->
	<div class="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
		<div class="overflow-x-auto">
			<table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
				<thead class="bg-gray-50 dark:bg-gray-700">
					<tr>
						<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
							Template
						</th>
						<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
							Type & Purpose
						</th>
						<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
							Status
						</th>
						<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
							Last Updated
						</th>
						<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
							Actions
						</th>
					</tr>
				</thead>
				<tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
					{#if loading}
						<tr>
							<td colspan="5" class="px-6 py-4 text-center text-gray-500 dark:text-gray-400">
								Loading templates...
							</td>
						</tr>
					{:else if templates.length === 0}
						<tr>
							<td colspan="5" class="px-6 py-4 text-center text-gray-500 dark:text-gray-400">
								No templates found
							</td>
						</tr>
					{:else}
						{#each templates as template}
							<tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
								<td class="px-6 py-4">
									<div class="text-sm">
										<div class="font-medium text-gray-900 dark:text-white">
											{template.subject || `${template.type.toUpperCase()} Template`}
										</div>
										<div class="text-gray-500 dark:text-gray-400 mt-1">
											Language: {template.language.toUpperCase()}
										</div>
										{#if template.is_default}
											<span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200 mt-1">
												Default
											</span>
										{/if}
									</div>
								</td>
								<td class="px-6 py-4 whitespace-nowrap">
									<div class="flex flex-col space-y-1">
										<span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full {getTypeBadge(template.type)}">
											{template.type.toUpperCase()}
										</span>
										<span class="text-sm text-gray-500 dark:text-gray-400 capitalize">
											{template.purpose.replace('_', ' ')}
										</span>
									</div>
								</td>
								<td class="px-6 py-4 whitespace-nowrap">
									{#if template.is_active}
										<span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
											Active
										</span>
									{:else}
										<span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
											Inactive
										</span>
									{/if}
								</td>
								<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
									{formatDate(template.updated_at)}
								</td>
								<td class="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2">
									<button
										type="button"
										class="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300"
										on:click={() => openPreviewModal(template)}
									>
										Preview
									</button>
									<button
										type="button"
										class="text-green-600 hover:text-green-900 dark:text-green-400 dark:hover:text-green-300"
										on:click={() => openEditModal(template)}
									>
										Edit
									</button>
									<button
										type="button"
										class="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
										on:click={() => deleteTemplate(template)}
									>
										Delete
									</button>
								</td>
							</tr>
						{/each}
					{/if}
				</tbody>
			</table>
		</div>

		<!-- Pagination -->
		<div class="bg-white dark:bg-gray-800 px-4 py-3 flex items-center justify-between border-t border-gray-200 dark:border-gray-700 sm:px-6">
			<div class="flex-1 flex justify-between sm:hidden">
				<button
					type="button"
					class="relative inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50"
					disabled={filter.offset === 0}
					on:click={prevPage}
				>
					Previous
				</button>
				<button
					type="button"
					class="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50"
					disabled={filter.offset + filter.limit >= total}
					on:click={nextPage}
				>
					Next
				</button>
			</div>
			<div class="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
				<div>
					<p class="text-sm text-gray-700 dark:text-gray-300">
						Showing <span class="font-medium">{filter.offset + 1}</span> to <span class="font-medium">{Math.min(filter.offset + filter.limit, total)}</span> of <span class="font-medium">{total}</span> results
					</p>
				</div>
				<div>
					<nav class="relative z-0 inline-flex rounded-md shadow-sm -space-x-px">
						<button
							type="button"
							class="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm font-medium text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50"
							disabled={filter.offset === 0}
							on:click={prevPage}
						>
							Previous
						</button>
						<button
							type="button"
							class="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm font-medium text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50"
							disabled={filter.offset + filter.limit >= total}
							on:click={nextPage}
						>
							Next
						</button>
					</nav>
				</div>
			</div>
		</div>
	</div>
</div>

<!-- Create Template Modal -->
{#if showCreateModal}
	<div class="fixed inset-0 z-50 overflow-y-auto">
		<div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
			<div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" on:click={() => showCreateModal = false}></div>

			<div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-2xl sm:w-full">
				<form on:submit|preventDefault={createTemplate}>
					<div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
						<h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
							Create New Template
						</h3>
						
						<div class="space-y-4">
							<div class="grid grid-cols-2 gap-4">
								<div>
									<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
										Type *
									</label>
									<select
										required
										class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
										bind:value={templateForm.type}
									>
										<option value="email">Email</option>
										<option value="sms">SMS</option>
									</select>
								</div>
								
								<div>
									<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
										Purpose *
									</label>
									<select
										required
										class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
										bind:value={templateForm.purpose}
									>
										{#each templatePurposes as purpose}
											<option value={purpose.value}>{purpose.label}</option>
										{/each}
									</select>
								</div>
							</div>
							
							<div>
								<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
									Language *
								</label>
								<select
									required
									class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
									bind:value={templateForm.language}
								>
									<option value="en">English</option>
									<option value="es">Spanish</option>
									<option value="fr">French</option>
								</select>
							</div>
							
							{#if templateForm.type === 'email'}
								<div>
									<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
										Subject *
									</label>
									<input
										type="text"
										required
										class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
										placeholder="Email subject line"
										bind:value={templateForm.subject}
									/>
								</div>
							{/if}
							
							<div>
								<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
									Content *
								</label>
								<textarea
									required
									rows="8"
									class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
									placeholder="Template content with variables like {{code}}, {{user_name}}, etc."
									bind:value={templateForm.content}
								></textarea>
								<p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
									Use double curly braces for variables: {{code}}, {{user_name}}, {{expiration}}
								</p>
							</div>
							
							<div class="flex items-center space-x-4">
								<label class="flex items-center">
									<input
										type="checkbox"
										class="rounded border-gray-300 dark:border-gray-600 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
										bind:checked={templateForm.is_default}
									/>
									<span class="ml-2 text-sm text-gray-700 dark:text-gray-300">Set as default</span>
								</label>
								
								<label class="flex items-center">
									<input
										type="checkbox"
										class="rounded border-gray-300 dark:border-gray-600 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
										bind:checked={templateForm.is_active}
									/>
									<span class="ml-2 text-sm text-gray-700 dark:text-gray-300">Active</span>
								</label>
							</div>
						</div>
					</div>
					
					<div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
						<button
							type="submit"
							class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-blue-600 text-base font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:ml-3 sm:w-auto sm:text-sm"
						>
							Create Template
						</button>
						<button
							type="button"
							class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 shadow-sm px-4 py-2 bg-white dark:bg-gray-800 text-base font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
							on:click={() => showCreateModal = false}
						>
							Cancel
						</button>
					</div>
				</form>
			</div>
		</div>
	</div>
{/if}

<!-- Edit Template Modal -->
{#if showEditModal && selectedTemplate}
	<div class="fixed inset-0 z-50 overflow-y-auto">
		<div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
			<div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" on:click={() => showEditModal = false}></div>

			<div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-2xl sm:w-full">
				<form on:submit|preventDefault={updateTemplate}>
					<div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
						<h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
							Edit Template
						</h3>
						
						<div class="space-y-4">
							{#if templateForm.type === 'email'}
								<div>
									<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
										Subject *
									</label>
									<input
										type="text"
										required
										class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
										bind:value={templateForm.subject}
									/>
								</div>
							{/if}
							
							<div>
								<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
									Content *
								</label>
								<textarea
									required
									rows="8"
									class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
									bind:value={templateForm.content}
								></textarea>
							</div>
							
							<div>
								<label class="flex items-center">
									<input
										type="checkbox"
										class="rounded border-gray-300 dark:border-gray-600 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
										bind:checked={templateForm.is_active}
									/>
									<span class="ml-2 text-sm text-gray-700 dark:text-gray-300">Active</span>
								</label>
							</div>
						</div>
					</div>
					
					<div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
						<button
							type="submit"
							class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-blue-600 text-base font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:ml-3 sm:w-auto sm:text-sm"
						>
							Update Template
						</button>
						<button
							type="button"
							class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 shadow-sm px-4 py-2 bg-white dark:bg-gray-800 text-base font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
							on:click={() => showEditModal = false}
						>
							Cancel
						</button>
					</div>
				</form>
			</div>
		</div>
	</div>
{/if}

<!-- Preview Template Modal -->
{#if showPreviewModal && selectedTemplate}
	<div class="fixed inset-0 z-50 overflow-y-auto">
		<div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
			<div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" on:click={() => showPreviewModal = false}></div>

			<div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-4xl sm:w-full">
				<div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
					<h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
						Template Preview - {selectedTemplate.type.toUpperCase()} ({selectedTemplate.purpose})
					</h3>
					
					<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
						<!-- Variables -->
						<div>
							<h4 class="text-md font-medium text-gray-900 dark:text-white mb-3">Variables</h4>
							<div class="space-y-3">
								{#each availableVariables as variable}
									<div>
										<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
											{variable.name} {variable.required ? '*' : ''}
										</label>
										<input
											type="text"
											class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white text-sm"
											placeholder={variable.example}
											bind:value={previewVariables[variable.name]}
											on:input={generatePreview}
										/>
										<p class="text-xs text-gray-500 dark:text-gray-400 mt-1">{variable.description}</p>
									</div>
								{/each}
							</div>
						</div>
						
						<!-- Preview -->
						<div>
							<h4 class="text-md font-medium text-gray-900 dark:text-white mb-3">Preview</h4>
							<div class="border border-gray-300 dark:border-gray-600 rounded-lg p-4 bg-gray-50 dark:bg-gray-700">
								{#if selectedTemplate.type === 'email' && previewResult.rendered_subject}
									<div class="mb-3">
										<strong class="text-sm text-gray-700 dark:text-gray-300">Subject:</strong>
										<div class="text-sm text-gray-900 dark:text-white mt-1 font-medium">
											{previewResult.rendered_subject}
										</div>
									</div>
									<hr class="border-gray-300 dark:border-gray-600 mb-3" />
								{/if}
								
								<div class="text-sm text-gray-900 dark:text-white whitespace-pre-wrap">
									{previewResult.rendered_content}
								</div>
							</div>
						</div>
					</div>
				</div>
				
				<div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
					<button
						type="button"
						class="w-full inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 shadow-sm px-4 py-2 bg-white dark:bg-gray-800 text-base font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:w-auto sm:text-sm"
						on:click={() => showPreviewModal = false}
					>
						Close
					</button>
				</div>
			</div>
		</div>
	</div>
{/if}