// Duplicate File Analyzer Web Interface

class DuplicateAnalyzer {
  constructor() {
    this.currentSessionId = null;
    this.websocket = null;
    this.currentResults = null;
    this.currentView = "duplicates";
    this.sortColumn = "path";
    this.sortDirection = "asc";
    this.selectedFiles = new Set();
    this.initializeEventListeners();
    this.connectWebSocket();
  }

  initializeEventListeners() {
    const form = document.getElementById("analysis-form");
    form.addEventListener("submit", (e) => this.handleStartAnalysis(e));

    // View toggle buttons
    document
      .getElementById("duplicate-view-btn")
      .addEventListener("click", () => this.showDuplicateView());
    document
      .getElementById("file-list-view-btn")
      .addEventListener("click", () => this.showFileListView());

    // Export buttons
    document
      .getElementById("export-json-btn")
      .addEventListener("click", () => this.exportResults("json"));
    document
      .getElementById("export-csv-btn")
      .addEventListener("click", () => this.exportResults("csv"));
    document
      .getElementById("export-html-btn")
      .addEventListener("click", () => this.exportResults("html"));

    // File list controls
    document
      .getElementById("file-search")
      .addEventListener("input", (e) => this.filterFiles(e.target.value));
    document
      .getElementById("file-filter")
      .addEventListener("change", (e) =>
        this.filterFilesByType(e.target.value)
      );

    // Select all checkbox
    document
      .getElementById("select-all-files")
      .addEventListener("change", (e) =>
        this.toggleSelectAll(e.target.checked)
      );

    // Bulk actions
    document
      .getElementById("bulk-delete-btn")
      .addEventListener("click", () => this.bulkDeleteFiles());
    document
      .getElementById("bulk-export-btn")
      .addEventListener("click", () => this.exportSelectedFiles());

    // Table sorting
    document.querySelectorAll(".sortable").forEach((header) => {
      header.addEventListener("click", () =>
        this.sortTable(header.dataset.sort)
      );
    });
  }

  connectWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    this.websocket = new WebSocket(wsUrl);

    this.websocket.onopen = () => {
      console.log("WebSocket connected");
    };

    this.websocket.onmessage = (event) => {
      const data = JSON.parse(event.data);
      this.handleWebSocketMessage(data);
    };

    this.websocket.onclose = () => {
      console.log("WebSocket disconnected");
      // Attempt to reconnect after 3 seconds
      setTimeout(() => this.connectWebSocket(), 3000);
    };

    this.websocket.onerror = (error) => {
      console.error("WebSocket error:", error);
    };
  }

  handleWebSocketMessage(data) {
    switch (data.type) {
      case "connected":
        console.log("WebSocket connection established");
        break;
      case "progress":
        this.updateProgress(data.data);
        break;
      case "completed":
        this.handleAnalysisComplete(data.data);
        break;
      case "error":
        this.handleAnalysisError(data.data);
        break;
    }
  }

  async handleStartAnalysis(event) {
    event.preventDefault();

    const formData = new FormData(event.target);
    const targetDirectory = formData.get("targetDirectory");
    const hashAlgorithm = formData.get("hashAlgorithm");
    const excludePatterns = formData.get("excludePatterns");

    const request = {
      target_directory: targetDirectory,
      options: {
        hash_algorithm: hashAlgorithm,
        thread_count: null,
        follow_symlinks: false,
      },
      exclude_patterns: excludePatterns
        ? excludePatterns.split(",").map((p) => p.trim())
        : null,
    };

    try {
      const response = await fetch("/api/analysis", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
      });

      if (response.ok) {
        const session = await response.json();
        this.currentSessionId = session.session_id;
        this.showProgressSection();
        this.startProgressPolling();
      } else {
        alert("Failed to start analysis");
      }
    } catch (error) {
      console.error("Error starting analysis:", error);
      alert("Error starting analysis");
    }
  }

  showProgressSection() {
    document.getElementById("progress-section").style.display = "block";
    document.getElementById("results-section").style.display = "none";
  }

  showResultsSection() {
    document.getElementById("progress-section").style.display = "none";
    document.getElementById("results-section").style.display = "block";
  }

  updateProgress(progressData) {
    const progressFill = document.getElementById("progress-fill");
    const progressText = document.getElementById("progress-text");
    const currentFile = document.getElementById("current-file");

    const percentage = progressData.progress_percentage || 0;
    progressFill.style.width = `${percentage}%`;
    progressText.textContent = `${percentage.toFixed(1)}% complete`;

    if (progressData.current_file) {
      currentFile.textContent = `Processing: ${progressData.current_file}`;
    }
  }

  async startProgressPolling() {
    if (!this.currentSessionId) return;

    const pollInterval = setInterval(async () => {
      try {
        const response = await fetch(`/api/analysis/${this.currentSessionId}`);
        if (response.ok) {
          const session = await response.json();

          if (session.status === "Completed") {
            clearInterval(pollInterval);
            await this.loadResults();
          } else if (session.status === "Failed") {
            clearInterval(pollInterval);
            alert("Analysis failed");
          }
        }
      } catch (error) {
        console.error("Error polling status:", error);
      }
    }, 1000);
  }

  async loadResults() {
    if (!this.currentSessionId) return;

    try {
      const response = await fetch(
        `/api/analysis/${this.currentSessionId}/results`
      );
      if (response.ok) {
        const results = await response.json();
        this.displayResults(results);
        this.showResultsSection();
      }
    } catch (error) {
      console.error("Error loading results:", error);
    }
  }

  displayResults(results) {
    this.currentResults = results;
    const summaryDiv = document.getElementById("results-summary");
    const duplicateSetsDiv = document.getElementById("duplicate-sets");

    // Display summary
    summaryDiv.innerHTML = `
            <h3>Analysis Summary</h3>
            <p><strong>Total Files Analyzed:</strong> ${
              results.total_files_analyzed
            }</p>
            <p><strong>Duplicate Files Found:</strong> ${
              results.total_duplicate_files
            }</p>
            <p><strong>Potential Space Savings:</strong> ${this.formatBytes(
              results.total_potential_savings
            )}</p>
            <p><strong>Analysis Time:</strong> ${results.analysis_time.toFixed(
              2
            )} seconds</p>
        `;

    // Display duplicate sets
    duplicateSetsDiv.innerHTML = "";
    results.duplicate_sets.forEach((duplicateSet, index) => {
      const setDiv = this.createDuplicateSetElement(duplicateSet, index);
      duplicateSetsDiv.appendChild(setDiv);
    });

    // Initialize file list view
    this.initializeFileListView();
  }

  createDuplicateSetElement(duplicateSet, index) {
    const setDiv = document.createElement("div");
    setDiv.className = "duplicate-set";

    const headerDiv = document.createElement("div");
    headerDiv.className = "duplicate-set-header";
    headerDiv.innerHTML = `
            <span>Duplicate Set ${index + 1} (${
      duplicateSet.files.length
    } files)</span>
            <span class="space-savings">Potential Savings: ${this.formatBytes(
              duplicateSet.potential_savings
            )}</span>
        `;

    const filesDiv = document.createElement("div");
    filesDiv.className = "duplicate-set-files";

    duplicateSet.files.forEach((file) => {
      const fileDiv = document.createElement("div");
      fileDiv.className = "file-item";
      fileDiv.innerHTML = `
                <input type="checkbox" class="file-checkbox" data-file-path="${
                  file.path
                }" />
                <a href="#" class="file-path" data-file-path="${file.path}">${
        file.path
      }</a>
                <span class="file-meta">${this.formatBytes(
                  file.size
                )} | ${new Date(file.modified_time).toLocaleString()}</span>
                <div class="file-actions">
                    <button class="delete-btn" data-file-path="${
                      file.path
                    }">Delete</button>
                </div>
            `;

      // Add event listeners for this file item
      const checkbox = fileDiv.querySelector(".file-checkbox");
      checkbox.addEventListener("change", (e) =>
        this.toggleFileSelection(e.target.dataset.filePath, e.target.checked)
      );

      const fileLink = fileDiv.querySelector(".file-path");
      fileLink.addEventListener("click", (e) => {
        e.preventDefault();
        this.openFileLocation(e.target.dataset.filePath);
      });

      const deleteBtn = fileDiv.querySelector(".delete-btn");
      deleteBtn.addEventListener("click", (e) =>
        this.deleteFile(e.target.dataset.filePath)
      );

      filesDiv.appendChild(fileDiv);
    });

    headerDiv.addEventListener("click", () => {
      filesDiv.classList.toggle("expanded");
    });

    setDiv.appendChild(headerDiv);
    setDiv.appendChild(filesDiv);

    return setDiv;
  }

  formatBytes(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  openFileLocation(filePath) {
    // This would typically open the file location in the system file manager
    // For now, just log the action
    console.log("Opening file location:", filePath);
    alert(`Would open file location: ${filePath}`);
  }

  async deleteFile(filePath) {
    const confirmed = await this.showConfirmationDialog(
      "Delete File",
      `Are you sure you want to delete this file?\n\n${filePath}`,
      "Delete",
      "Cancel"
    );

    if (!confirmed) return;

    try {
      const response = await fetch("/api/files/delete", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ file_path: filePath }),
      });

      if (response.ok) {
        const result = await response.json();
        if (result.success) {
          this.showNotification("File deleted successfully", "success");
          // Refresh results
          await this.loadResults();
        } else {
          this.showNotification(
            result.error || "Failed to delete file",
            "error"
          );
        }
      } else {
        this.showNotification("Failed to delete file", "error");
      }
    } catch (error) {
      console.error("Error deleting file:", error);
      this.showNotification("Error deleting file", "error");
    }
  }

  // View management methods
  showDuplicateView() {
    this.currentView = "duplicates";
    document.getElementById("duplicate-view-btn").classList.add("active");
    document.getElementById("file-list-view-btn").classList.remove("active");
    document.getElementById("duplicate-sets-view").style.display = "block";
    document.getElementById("file-list-view").style.display = "none";
  }

  showFileListView() {
    this.currentView = "files";
    document.getElementById("file-list-view-btn").classList.add("active");
    document.getElementById("duplicate-view-btn").classList.remove("active");
    document.getElementById("file-list-view").style.display = "block";
    document.getElementById("duplicate-sets-view").style.display = "none";
  }

  // File selection methods
  toggleFileSelection(filePath, selected) {
    if (selected) {
      this.selectedFiles.add(filePath);
    } else {
      this.selectedFiles.delete(filePath);
    }
    this.updateBulkActionsVisibility();
  }

  toggleSelectAll(selectAll) {
    const checkboxes = document.querySelectorAll(".file-checkbox");
    checkboxes.forEach((checkbox) => {
      checkbox.checked = selectAll;
      this.toggleFileSelection(checkbox.dataset.filePath, selectAll);
    });
  }

  updateBulkActionsVisibility() {
    const bulkActions = document.getElementById("bulk-actions");
    if (this.selectedFiles.size > 0) {
      bulkActions.style.display = "flex";
      bulkActions.querySelector(
        "::before"
      ).textContent = `${this.selectedFiles.size} files selected:`;
    } else {
      bulkActions.style.display = "none";
    }
  }

  // Bulk operations
  async bulkDeleteFiles() {
    if (this.selectedFiles.size === 0) return;

    const fileList = Array.from(this.selectedFiles).join("\n");
    const confirmed = await this.showConfirmationDialog(
      "Delete Multiple Files",
      `Are you sure you want to delete ${this.selectedFiles.size} files?\n\n${fileList}`,
      "Delete All",
      "Cancel"
    );

    if (!confirmed) return;

    const deletePromises = Array.from(this.selectedFiles).map(
      async (filePath) => {
        try {
          const response = await fetch("/api/files/delete", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ file_path: filePath }),
          });

          if (response.ok) {
            const result = await response.json();
            return { filePath, success: result.success };
          } else {
            return { filePath, success: false };
          }
        } catch (error) {
          return { filePath, success: false, error };
        }
      }
    );

    const results = await Promise.all(deletePromises);
    const successful = results.filter((r) => r.success).length;
    const failed = results.filter((r) => !r.success).length;

    if (successful > 0) {
      this.showNotification(
        `Successfully deleted ${successful} files`,
        "success"
      );
    }
    if (failed > 0) {
      this.showNotification(`Failed to delete ${failed} files`, "error");
    }

    this.selectedFiles.clear();
    this.updateBulkActionsVisibility();
    await this.loadResults();
  }

  // File list view methods
  initializeFileListView() {
    if (!this.currentResults) return;

    const tableBody = document.getElementById("file-table-body");
    tableBody.innerHTML = "";

    // Collect all files from duplicate sets and add unique files
    const allFiles = [];
    const duplicateFiles = new Set();

    this.currentResults.duplicate_sets.forEach((set) => {
      set.files.forEach((file) => {
        allFiles.push({
          ...file,
          duplicateCount: set.files.length,
          isDuplicate: true,
        });
        duplicateFiles.add(file.path);
      });
    });

    // Add unique files (this would need to come from the API)
    // For now, we'll just show duplicate files

    this.renderFileTable(allFiles);
  }

  renderFileTable(files) {
    const tableBody = document.getElementById("file-table-body");
    tableBody.innerHTML = "";

    files.forEach((file) => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td data-label="Select">
          <input type="checkbox" class="file-checkbox" data-file-path="${
            file.path
          }" />
        </td>
        <td data-label="Path" class="file-path-cell">
          <a href="#" data-file-path="${file.path}">${file.path}</a>
        </td>
        <td data-label="Size">${this.formatBytes(file.size)}</td>
        <td data-label="Modified">${new Date(
          file.modified_time
        ).toLocaleString()}</td>
        <td data-label="Duplicates">
          ${
            file.isDuplicate
              ? `<span class="duplicate-count">${file.duplicateCount} duplicates</span>`
              : `<span class="unique-file">Unique</span>`
          }
        </td>
        <td data-label="Actions">
          <button class="delete-btn" data-file-path="${
            file.path
          }">Delete</button>
        </td>
      `;

      // Add event listeners
      const checkbox = row.querySelector(".file-checkbox");
      checkbox.addEventListener("change", (e) =>
        this.toggleFileSelection(e.target.dataset.filePath, e.target.checked)
      );

      const fileLink = row.querySelector("a");
      fileLink.addEventListener("click", (e) => {
        e.preventDefault();
        this.openFileLocation(e.target.dataset.filePath);
      });

      const deleteBtn = row.querySelector(".delete-btn");
      deleteBtn.addEventListener("click", (e) =>
        this.deleteFile(e.target.dataset.filePath)
      );

      tableBody.appendChild(row);
    });
  }

  // Filtering and sorting
  filterFiles(searchTerm) {
    const rows = document.querySelectorAll("#file-table-body tr");
    rows.forEach((row) => {
      const filePath = row
        .querySelector(".file-path-cell a")
        .textContent.toLowerCase();
      const matches = filePath.includes(searchTerm.toLowerCase());
      row.style.display = matches ? "" : "none";
    });
  }

  filterFilesByType(filterType) {
    const rows = document.querySelectorAll("#file-table-body tr");
    rows.forEach((row) => {
      const isDuplicate = row.querySelector(".duplicate-count") !== null;
      let show = true;

      switch (filterType) {
        case "duplicates":
          show = isDuplicate;
          break;
        case "unique":
          show = !isDuplicate;
          break;
        case "all":
        default:
          show = true;
          break;
      }

      row.style.display = show ? "" : "none";
    });
  }

  sortTable(column) {
    if (this.sortColumn === column) {
      this.sortDirection = this.sortDirection === "asc" ? "desc" : "asc";
    } else {
      this.sortColumn = column;
      this.sortDirection = "asc";
    }

    // Update sort indicators
    document.querySelectorAll(".sortable").forEach((header) => {
      header.classList.remove("sort-asc", "sort-desc");
    });

    const currentHeader = document.querySelector(`[data-sort="${column}"]`);
    currentHeader.classList.add(`sort-${this.sortDirection}`);

    // Sort the table rows
    const tableBody = document.getElementById("file-table-body");
    const rows = Array.from(tableBody.querySelectorAll("tr"));

    rows.sort((a, b) => {
      let aValue, bValue;

      switch (column) {
        case "path":
          aValue = a.querySelector(".file-path-cell a").textContent;
          bValue = b.querySelector(".file-path-cell a").textContent;
          break;
        case "size":
          aValue = parseInt(a.cells[2].dataset.size || "0");
          bValue = parseInt(b.cells[2].dataset.size || "0");
          break;
        case "modified":
          aValue = new Date(a.cells[3].textContent);
          bValue = new Date(b.cells[3].textContent);
          break;
        case "duplicates":
          aValue = a.querySelector(".duplicate-count")
            ? parseInt(a.querySelector(".duplicate-count").textContent)
            : 0;
          bValue = b.querySelector(".duplicate-count")
            ? parseInt(b.querySelector(".duplicate-count").textContent)
            : 0;
          break;
        default:
          return 0;
      }

      if (aValue < bValue) return this.sortDirection === "asc" ? -1 : 1;
      if (aValue > bValue) return this.sortDirection === "asc" ? 1 : -1;
      return 0;
    });

    // Re-append sorted rows
    rows.forEach((row) => tableBody.appendChild(row));
  }

  // Confirmation dialog
  showConfirmationDialog(title, message, confirmText, cancelText) {
    return new Promise((resolve) => {
      const dialog = document.createElement("div");
      dialog.className = "confirmation-dialog";
      dialog.innerHTML = `
        <div class="confirmation-content">
          <h3>${title}</h3>
          <p>${message}</p>
          <div class="confirmation-actions">
            <button class="confirm-btn">${confirmText}</button>
            <button class="cancel-btn">${cancelText}</button>
          </div>
        </div>
      `;

      const confirmBtn = dialog.querySelector(".confirm-btn");
      const cancelBtn = dialog.querySelector(".cancel-btn");

      confirmBtn.addEventListener("click", () => {
        document.body.removeChild(dialog);
        resolve(true);
      });

      cancelBtn.addEventListener("click", () => {
        document.body.removeChild(dialog);
        resolve(false);
      });

      // Close on background click
      dialog.addEventListener("click", (e) => {
        if (e.target === dialog) {
          document.body.removeChild(dialog);
          resolve(false);
        }
      });

      document.body.appendChild(dialog);
    });
  }

  // Notification system
  showNotification(message, type = "info") {
    const notification = document.createElement("div");
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 15px 20px;
      border-radius: 4px;
      color: white;
      font-weight: 500;
      z-index: 1001;
      max-width: 300px;
      word-wrap: break-word;
    `;

    switch (type) {
      case "success":
        notification.style.backgroundColor = "#28a745";
        break;
      case "error":
        notification.style.backgroundColor = "#dc3545";
        break;
      case "warning":
        notification.style.backgroundColor = "#ffc107";
        notification.style.color = "#212529";
        break;
      default:
        notification.style.backgroundColor = "#17a2b8";
    }

    document.body.appendChild(notification);

    setTimeout(() => {
      if (document.body.contains(notification)) {
        document.body.removeChild(notification);
      }
    }, 5000);
  }

  // Export functionality
  exportResults(format) {
    if (!this.currentResults) return;

    let content, filename, mimeType;

    switch (format) {
      case "json":
        content = JSON.stringify(this.currentResults, null, 2);
        filename = `duplicate-analysis-${
          new Date().toISOString().split("T")[0]
        }.json`;
        mimeType = "application/json";
        break;
      case "csv":
        content = this.generateCSV(this.currentResults);
        filename = `duplicate-analysis-${
          new Date().toISOString().split("T")[0]
        }.csv`;
        mimeType = "text/csv";
        break;
      case "html":
        content = this.generateHTML(this.currentResults);
        filename = `duplicate-analysis-${
          new Date().toISOString().split("T")[0]
        }.html`;
        mimeType = "text/html";
        break;
      default:
        return;
    }

    this.downloadFile(content, filename, mimeType);
  }

  exportSelectedFiles() {
    if (this.selectedFiles.size === 0) {
      this.showNotification("No files selected for export", "warning");
      return;
    }

    const selectedData = {
      exported_at: new Date().toISOString(),
      selected_files: Array.from(this.selectedFiles),
      file_count: this.selectedFiles.size,
    };

    const content = JSON.stringify(selectedData, null, 2);
    const filename = `selected-files-${
      new Date().toISOString().split("T")[0]
    }.json`;
    this.downloadFile(content, filename, "application/json");
  }

  generateCSV(results) {
    const headers = [
      "File Path",
      "Size (Bytes)",
      "Size (Formatted)",
      "Modified Date",
      "Duplicate Set",
      "Potential Savings",
    ];
    const rows = [headers];

    results.duplicate_sets.forEach((set, setIndex) => {
      set.files.forEach((file) => {
        rows.push([
          file.path,
          file.size,
          this.formatBytes(file.size),
          new Date(file.modified_time).toISOString(),
          `Set ${setIndex + 1}`,
          this.formatBytes(set.potential_savings),
        ]);
      });
    });

    return rows
      .map((row) =>
        row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(",")
      )
      .join("\n");
  }

  generateHTML(results) {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Duplicate File Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .duplicate-set { border: 1px solid #ddd; margin-bottom: 15px; border-radius: 5px; }
        .set-header { background: #e9ecef; padding: 10px; font-weight: bold; }
        .file-list { padding: 10px; }
        .file-item { padding: 5px 0; border-bottom: 1px solid #eee; }
        .space-savings { color: #28a745; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Duplicate File Analysis Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Files Analyzed:</strong> ${
          results.total_files_analyzed
        }</p>
        <p><strong>Duplicate Files Found:</strong> ${
          results.total_duplicate_files
        }</p>
        <p><strong>Potential Space Savings:</strong> ${this.formatBytes(
          results.total_potential_savings
        )}</p>
        <p><strong>Analysis Time:</strong> ${results.analysis_time.toFixed(
          2
        )} seconds</p>
        <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
    </div>
    
    <h2>Duplicate Sets</h2>
    ${results.duplicate_sets
      .map(
        (set, index) => `
        <div class="duplicate-set">
            <div class="set-header">
                Duplicate Set ${index + 1} (${set.files.length} files) - 
                <span class="space-savings">Potential Savings: ${this.formatBytes(
                  set.potential_savings
                )}</span>
            </div>
            <div class="file-list">
                ${set.files
                  .map(
                    (file) => `
                    <div class="file-item">
                        <strong>Path:</strong> ${file.path}<br>
                        <strong>Size:</strong> ${this.formatBytes(
                          file.size
                        )}<br>
                        <strong>Modified:</strong> ${new Date(
                          file.modified_time
                        ).toLocaleString()}
                    </div>
                `
                  )
                  .join("")}
            </div>
        </div>
    `
      )
      .join("")}
</body>
</html>`;
  }

  downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    this.showNotification(`Exported ${filename}`, "success");
  }

  handleAnalysisComplete(data) {
    console.log("Analysis completed:", data);
  }

  handleAnalysisError(data) {
    console.error("Analysis error:", data);
    this.showNotification("Analysis failed: " + data.message, "error");
  }
}

// Initialize the application when the page loads
document.addEventListener("DOMContentLoaded", () => {
  new DuplicateAnalyzer();
});
