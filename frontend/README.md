# ThreatSentinel Frontend

A sophisticated React-based frontend for the ThreatSentinel SOC Agent, designed specifically for security operations center analysts.

## Features

### 🎯 **Analyst-Focused Design**
- **Dark Theme**: Optimized for long hours of security monitoring
- **Real-time Updates**: Live data streaming and automatic refresh
- **Responsive Layout**: Works seamlessly on desktop, tablet, and mobile
- **Accessibility**: WCAG compliant with keyboard navigation support

### 📊 **Dashboard & Analytics**
- **Real-time Metrics**: Live threat activity, system health, and performance indicators
- **Interactive Charts**: Threat activity visualization with Recharts
- **Quick Actions**: One-click access to common SOC tasks
- **System Status**: Real-time monitoring of agent health and performance

### 🔍 **Investigation Management**
- **Investigation Creation**: Intuitive forms with event type selection
- **Advanced Filtering**: Search by status, risk level, event type, and more
- **Bulk Operations**: Multi-select actions for efficiency
- **Timeline View**: Chronological investigation tracking

### 📈 **Monitoring & Alerts**
- **Real-time Monitoring**: Live system metrics and performance data
- **Alert Management**: Centralized alert viewing and management
- **WebSocket Integration**: Real-time data streaming
- **Historical Data**: Trend analysis and performance tracking

### 🔧 **Integration Management**
- **SOC Tool Integration**: Manage connections to firewalls, SIEMs, and more
- **Action Execution**: Direct control over security tool actions
- **Health Monitoring**: Integration status and performance tracking
- **Configuration Management**: Easy setup and maintenance

### 📋 **Task & Audit Management**
- **Task Queue**: Priority-based task management with status tracking
- **Audit Trails**: Comprehensive logging and compliance reporting
- **Performance Analytics**: Component performance and system health metrics
- **Export Capabilities**: Data export for compliance and reporting

## Technology Stack

- **React 18**: Modern React with hooks and functional components
- **React Router**: Client-side routing and navigation
- **React Query**: Server state management and caching
- **Tailwind CSS**: Utility-first CSS framework with custom dark theme
- **Recharts**: Interactive charts and data visualization
- **Lucide React**: Beautiful, customizable icons
- **React Hook Form**: Performant forms with validation
- **React Hot Toast**: Elegant notifications
- **Axios**: HTTP client for API communication

## Quick Start

### Prerequisites
- Node.js 16+ and npm
- ThreatSentinel backend running on `http://localhost:8000`

### Installation

1. **Navigate to the frontend directory:**
   ```bash
   cd frontend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the development server:**
   ```bash
   npm start
   ```

4. **Open your browser:**
   Navigate to `http://localhost:3000`

### Environment Configuration

Create a `.env` file in the frontend directory:

```env
REACT_APP_API_URL=http://localhost:8000
REACT_APP_WS_URL=ws://localhost:8000
```

## Project Structure

```
frontend/
├── public/                 # Static assets
├── src/
│   ├── components/         # Reusable UI components
│   │   ├── Dashboard/     # Dashboard-specific components
│   │   ├── Investigations/# Investigation management
│   │   ├── Layout/        # Layout and navigation
│   │   └── Common/        # Shared components
│   ├── pages/             # Page components
│   ├── context/           # React context providers
│   ├── hooks/             # Custom React hooks
│   ├── utils/             # Utility functions
│   └── styles/            # Global styles and themes
├── package.json
└── tailwind.config.js     # Tailwind configuration
```

## Key Components

### Dashboard Components
- **MetricCard**: Displays key performance indicators
- **ThreatActivityChart**: Real-time threat visualization
- **QuickActions**: Common SOC task shortcuts
- **SystemStatus**: Real-time system health monitoring
- **RecentInvestigations**: Latest investigation overview

### Investigation Components
- **InvestigationForm**: Create new investigations
- **InvestigationTable**: Manage investigation list
- **InvestigationDetail**: Detailed investigation view
- **InvestigationTimeline**: Chronological event tracking

### Layout Components
- **Layout**: Main application layout with sidebar
- **Navigation**: Sidebar navigation with status indicators
- **Header**: Top navigation with quick actions

## API Integration

The frontend integrates with the ThreatSentinel backend API through:

- **REST API**: Standard HTTP endpoints for CRUD operations
- **WebSockets**: Real-time data streaming for live updates
- **React Query**: Intelligent caching and state management
- **Error Handling**: Comprehensive error handling and user feedback

## Development

### Available Scripts

- `npm start`: Start development server
- `npm build`: Build for production
- `npm test`: Run test suite
- `npm eject`: Eject from Create React App

### Code Style

- **ESLint**: Code linting and formatting
- **Prettier**: Code formatting
- **TypeScript**: Type safety (optional)

### Testing

- **Jest**: Unit testing framework
- **React Testing Library**: Component testing
- **Mock Service Worker**: API mocking

## Deployment

### Production Build

1. **Build the application:**
   ```bash
   npm run build
   ```

2. **Serve the build folder:**
   ```bash
   npx serve -s build
   ```

### Docker Deployment

```dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["npm", "start"]
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

For support and questions:
- Check the main ThreatSentinel documentation
- Review the API documentation
- Open an issue on GitHub

## License

This project is licensed under the MIT License - see the LICENSE file for details. 