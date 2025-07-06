# Sidebar Management System

## Overview
The sidebar management system automatically synchronizes the markdown file list across all HTML pages in the Red Vault project. This means you only need to update the configuration in one place to reflect changes across all pages.

## How It Works

### 1. Configuration File
The sidebar configuration is centralized in `config/sidebar-config.js`. This file contains an array of objects, each representing a sidebar link:

```javascript
const SIDEBAR_CONFIG = [
    {
        title: "README.md",
        path: "Readme/Readme.md"
    },
    {
        title: "HTB - Planning",
        path: "planning/HBT - Planning.md"
    },
    // ... more entries
];
```

### 2. Sidebar Manager
The `js/sidebar-manager.js` file handles the dynamic generation and initialization of the sidebar:

- **generateSidebarHTML()**: Creates the HTML for sidebar links
- **initializeSidebar()**: Initializes the sidebar with event listeners
- **getAllMarkdownFiles()**: Returns all markdown files for search functionality

### 3. Automatic Synchronization
All HTML files (`index.html`, `home.html`, `resources.html`, `dev.html`) load both the configuration and manager scripts, ensuring they all display the same sidebar.

## How to Update the Sidebar

### Adding a New Markdown File
1. Open `config/sidebar-config.js`
2. Add a new object to the `SIDEBAR_CONFIG` array:
   ```javascript
   {
       title: "Your New Page Title",
       path: "folder/your-new-file.md"
   }
   ```
3. Save the file

### Modifying an Existing Entry
1. Open `config/sidebar-config.js`
2. Find the entry you want to modify
3. Update the `title` or `path` as needed
4. Save the file

### Removing an Entry
1. Open `config/sidebar-config.js`
2. Delete the entire object for the entry you want to remove
3. Save the file

## Benefits

1. **Single Source of Truth**: All sidebar configuration is in one place
2. **Automatic Synchronization**: Changes are reflected across all pages immediately
3. **No Manual Updates**: No need to manually update each HTML file
4. **Consistent Behavior**: All pages behave the same way
5. **Easy Maintenance**: Adding or removing pages is simple

## File Structure
```
RedVault/
├── config/
│   └── sidebar-config.js    # Central configuration
├── js/
│   └── sidebar-manager.js   # Sidebar management logic
├── index.html               # Main page (loads markdown files)
├── home.html               # Home page
├── resources.html          # Resources page
├── dev.html                # Developer page
└── README-SIDEBAR.md       # This documentation
```

## Notes
- The system automatically detects whether it's running on the main page (`index.html`) or other pages
- Only the main page (`index.html`) loads markdown files; other pages redirect to the main page
- The search functionality automatically uses the new configuration system
- All existing functionality remains unchanged for end users
