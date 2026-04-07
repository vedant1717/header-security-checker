# Header Shield: HTTP Validation & Security Checker

Header Shield is a highly aesthetic, purely client-side React + TypeScript web application designed to evaluate HTTP headers for security best practices. Because the logic is entirely front-end, the app can be compiled into static files and effortlessly hosted anywhere, allowing you to access it without the need for a complex backend server.

## Core Features
* **Raw Header Parsing**: Automatically extracts key-value pairs from raw, multi-line HTTP text dumps.
* **Security Rules Engine**: Actively grades crucial security headers such as HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
* **Access Control Checks**: Analyzes CORS headers (`Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Credentials`) to prevent unauthorized cross-origin resource sharing.
* **Server Leak Detection**: Assesses verbose infrastructural headers like `Server` and `X-Powered-By` as potential vulnerabilities.
* **Actionable Reporting**: Provides detailed remediation instructions to improve server security posture.
* **Auth-Protected Gateway**: Access is gated behind a lightweight, hashed-password login mechanism to prevent casual snooping.

## Demo Login
The application is secured. Upon opening the application, you will be prompted to login.
* **Username**: `vedantpatil`
* **Password**: `Kpmg@Vpatil!1717`  
*(Note: The password is not stored in plaintext anywhere in the source code; it is compared against a SHA-256 hash using the native Web Crypto API).*

---

## Installation & Setup Methods

### Method 1: Local Development (Running from Source)
If you want to modify the code or run the development server locally on your machine:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/vedantpatil/header-security-checker.git
   cd header-security-checker
   ```
2. **Install Node dependencies:** Ensure you have Node.js 20.19+ or 22.12+ installed.
   ```bash
   npm install
   ```
3. **Run the Vite Development Server:**
   ```bash
   npm run dev
   ```
4. Access the app by visiting `http://localhost:5173` in your browser.

### Method 2: Building for Production
If you want to compile the raw React application into static, high-performance HTML/CSS/JS files:

1. **Run the Build Command:**
   ```bash
   npm run build
   ```
2. **Serve or Host the Files:**
   The `dist/` directory will be generated. You can use any static server to serve these files. For example:
   ```bash
   npx serve -s dist
   ```

### Method 3: GitHub Pages Setup (Recommended for Always-On Access)
Because Header Shield requires no backend, you can automatically host it via GitHub Actions free of charge.

1. Go to your repository settings on GitHub.
2. Navigate to the **Pages** section on the left sidebar.
3. Under **Source**, select **GitHub Actions**.
4. GitHub should detect that it's a Vite project (or a Static HTML project) and let you configure it. If not, follow Vite's official GitHub Actions deployment workflow.
5. Once your action runs, your highly secure site will be live at `https://vedantpatil.github.io/header-security-checker`!

## Aesthetics & Design
* **Vanilla CSS Implementation:** Maintained tight control by avoiding utility frameworks and relying purely on standard, elegant CSS.
* **Glassmorphism Theme:** Achieved an ultra-premium dark mode leveraging `rgba` and `backdrop-filter` rules, creating deep, glowing UI panels layered across dynamic gradient backdrops.
