# Web Penetration Tool

This is a full-stack web penetration testing tool with a Python/Flask backend and a Next.js frontend. It provides a web-based user interface for running various security scans, including a 403 bypass scanner, an XSS scanner, an attack surface scanner, and a web crawler. It also includes an AI assistant to help analyze scan results.

## Prerequisites

Before you begin, ensure you have the following installed on your system:
- Python 3.8+
- Node.js 14.0+
- npm 6.0+

## Setup Instructions

The project is divided into two main parts: the `backend` and the `frontend`. You will need to run them in separate terminals.

### Backend Setup

1.  **Create and Activate a Virtual Environment (Recommended):**
    Before installing dependencies, it's a best practice to create a virtual environment.

    **Using `venv` (standard Python):**
    ```bash
    # Create the environment
    python -m venv venv
    # Activate it (on Windows)
    venv\\Scripts\\activate
    # Activate it (on macOS/Linux)
    source venv/bin/activate
    ```

    **Using `conda`:**
    ```bash
    # Create the environment
    conda create --name pen_tool_env python=3.9
    # Activate it
    conda activate pen_tool_env
    ```

2.  **Install Python dependencies from the dependency directory:**
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the Flask server from the dependency directory:**
    ```bash
    python backend/app.py
    ```
    The backend server will start on `http://localhost:5000`.

### Frontend Setup

1.  **Navigate to the frontend directory in a new terminal:**
    ```bash
    cd frontend
    ```

2.  **Install Node.js dependencies:**
    ```bash
    npm install
    ```

3.  **Run the Next.js development server:**
    ```bash
    npm run dev
    ```
    The frontend development server will start on `http://localhost:3001`.

## Usage

### 1. Accessing the Application
Open your web browser and navigate to `http://localhost:3001`. You will be greeted with the main dashboard.

### 2. Navigation
A persistent navigation bar at the top of the screen allows you to move between the main sections:
- **Scanners:** The main workspace for running all security scans.
- **History:** View the results of all past scans.
- **Settings:** Configure the AI assistant.

### 3. Configuring the AI Assistant ("R-T-F_Assistant")
Before using the AI assistant, you must configure it:
- Navigate to the **Settings** page.
- **Hugging Face API Key:** Enter your API key. This is required.
- **Model ID:** Optionally, provide a custom Hugging Face model ID. If left blank, it will use the default.
- Click "Save Settings".

### 4. Running Scans
- Navigate to the **Scanners** page. This is your main workspace.
- At the top of the workspace, you will find buttons to launch new scans:
  - **New Bypass Scan:** Tests for 403 bypass vulnerabilities.
  - **New XSS Scan:** Tests for Cross-Site Scripting vulnerabilities.
  - **New Surface Scan:** Performs subdomain and DNS record enumeration.
  - **New Port Scan:** Scans for open ports on a target.
  - **New Crawl:** Discovers links on a website.
- Clicking a button opens a new **draggable and resizable window** for that scan. You can open multiple windows at once.
- Inside each window, enter the target (URL, domain, or IP) and click the start button.
- Scan results will appear within the window once completed.

### 5. Using the "R-T-F_Assistant"
The AI assistant is located in a panel on the right side of the **Scanners** page.
- **Provide Context:** You can provide context to the AI in two ways (or both):
  - **Select Scan History:** Check the boxes next to any completed scan in the "Select Scan Context" section.
  - **Upload a File:** Use the "Upload a file" button to provide a text-based file (e.g., a log file, a code snippet) as context.
- **Ask a Question:** Type your question into the text area (e.g., "Are there any obvious misconfigurations in these results?") and click "Send".
- **Conversation History:** The chat is persistent for your session, allowing you to ask follow-up questions.

### 6. Viewing Scan History and Reports
- Navigate to the **History** page.
- This page displays a table of all scans you have run.
- For each scan, you can view the raw results.
- You can also download a formatted report in **HTML** or **PDF** format by clicking the corresponding links in the "Actions" column.
