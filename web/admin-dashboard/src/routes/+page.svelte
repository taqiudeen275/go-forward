<script lang="ts">
  import { Card, Button, Badge } from "$lib/components";
  import { theme, themeActions, roleThemes } from "$lib/stores/theme";
  import { currentUser } from "$lib/stores/auth";

  // Mock data for dashboard
  const stats = [
    { name: "Total Users", value: "12,345", change: "+12%", trend: "up" },
    { name: "Active Sessions", value: "1,234", change: "+5%", trend: "up" },
    { name: "API Requests", value: "98,765", change: "-2%", trend: "down" },
    { name: "Storage Used", value: "45.2 GB", change: "+8%", trend: "up" },
  ];

  const recentActivity = [
    {
      action: "User created",
      user: "john@example.com",
      time: "2 minutes ago",
      type: "success",
    },
    {
      action: "Login attempt failed",
      user: "admin@test.com",
      time: "5 minutes ago",
      type: "warning",
    },
    {
      action: "Table updated",
      user: "sarah@example.com",
      time: "10 minutes ago",
      type: "info",
    },
    {
      action: "File uploaded",
      user: "mike@example.com",
      time: "15 minutes ago",
      type: "success",
    },
  ];
</script>

<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
  <!-- Header -->
  <div class="mb-8">
    <h1 class="text-3xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
    <p class="mt-2 text-gray-600 dark:text-gray-400">
      Welcome back, {$currentUser?.name || "Admin"}!
    </p>
  </div>

  <!-- Role indicator card -->
  <Card class="mb-8 bg-gradient-to-r from-primary to-primary-hover text-white">
    <div class="flex items-center space-x-4">
      <div class="text-4xl">
        {roleThemes[$theme.role].icon}
      </div>
      <div>
        <h2 class="text-xl font-semibold">
          {roleThemes[$theme.role].name}
        </h2>
        <p class="text-blue-100">
          {roleThemes[$theme.role].description}
        </p>
      </div>
    </div>
  </Card>

  <!-- Stats Grid -->
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
    {#each stats as stat}
      <Card hover>
        <div class="flex items-center justify-between">
          <div>
            <p class="text-sm font-medium text-gray-600 dark:text-gray-400">
              {stat.name}
            </p>
            <p class="text-2xl font-bold text-gray-900 dark:text-white">
              {stat.value}
            </p>
          </div>
          <div class="text-right">
            <Badge
              variant={stat.trend === "up" ? "success" : "danger"}
              size="sm"
            >
              {stat.change}
            </Badge>
          </div>
        </div>
      </Card>
    {/each}
  </div>

  <!-- Content Grid -->
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
    <!-- Recent Activity -->
    <Card>
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
          Recent Activity
        </h3>
        <Button variant="ghost" size="sm">View All</Button>
      </div>

      <div class="space-y-4">
        {#each recentActivity as activity}
          <div
            class="flex items-center space-x-3 p-3 rounded-lg bg-gray-50 dark:bg-gray-700"
          >
            <div class="flex-shrink-0">
              <Badge
                variant={activity.type === "success"
                  ? "success"
                  : activity.type === "warning"
                    ? "warning"
                    : "info"}
                size="sm"
                rounded
              >
                {activity.type === "success"
                  ? "✓"
                  : activity.type === "warning"
                    ? "⚠"
                    : "ℹ"}
              </Badge>
            </div>
            <div class="flex-1 min-w-0">
              <p class="text-sm font-medium text-gray-900 dark:text-white">
                {activity.action}
              </p>
              <p class="text-sm text-gray-500 dark:text-gray-400">
                {activity.user}
              </p>
            </div>
            <div class="text-xs text-gray-400 dark:text-gray-500">
              {activity.time}
            </div>
          </div>
        {/each}
      </div>
    </Card>

    <!-- Theme Controls -->
    <Card>
      <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
        Theme Settings
      </h3>

      <div class="space-y-4">
        <div>
          <div
            class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2"
          >
            Theme Mode
          </div>
          <div class="flex space-x-2">
            <Button
              variant={$theme.mode === "light" ? "primary" : "secondary"}
              size="sm"
              onclick={() => themeActions.setMode("light")}
            >
              ☀️ Light
            </Button>
            <Button
              variant={$theme.mode === "dark" ? "primary" : "secondary"}
              size="sm"
              onclick={() => themeActions.setMode("dark")}
            >
              🌙 Dark
            </Button>
            <Button
              variant={$theme.mode === "system" ? "primary" : "secondary"}
              size="sm"
              onclick={() => themeActions.setMode("system")}
            >
              💻 System
            </Button>
          </div>
        </div>

        <div>
          <div
            class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2"
          >
            Role Theme (Demo)
          </div>
          <div class="grid grid-cols-2 gap-2">
            {#each Object.entries(roleThemes) as [role, config]}
              <Button
                variant={$theme.role === role ? "primary" : "secondary"}
                size="sm"
                onclick={() => themeActions.setRole(role)}
              >
                {config.icon}
                {config.name}
              </Button>
            {/each}
          </div>
        </div>
      </div>
    </Card>
  </div>

  <!-- Quick Actions -->
  <Card class="mt-8">
    <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
      Quick Actions
    </h3>

    <div class="flex flex-wrap gap-3">
      <Button variant="primary">👥 Manage Users</Button>
      <Button variant="secondary">📊 View Reports</Button>
      <Button variant="success">➕ Create New</Button>
      <Button variant="warning">⚙️ Settings</Button>
    </div>
  </Card>
</div>
