# ThreatSentinel frontend

React frontend for the ThreatSentinel SOC agent. Built for security analysts who live in it all day.

## Features

Dark theme tuned for long monitoring sessions. Live metrics over WebSockets with automatic refresh. Responsive layout for desktop, tablet, and mobile. Keyboard navigation throughout.

The dashboard shows threat activity, system health, and performance indicators, with Recharts for the charts. Investigations can be created from forms, filtered by status, risk level, or event type, and inspected in a timeline view. The monitoring page tracks system metrics and alert history. The integrations page manages connections to firewalls, SIEMs, and other tools, including direct action execution. A task queue view covers priority-based background work, and audit pages expose action logs for compliance.

## Technology stack

- React 18 with hooks and functional components
- React Router for client-side routing
- React Query for server state and caching
- Tailwind CSS with a custom dark theme
- Recharts for data visualization
- Lucide React for icons
- React Hook Form for forms and validation
- React Hot Toast for notifications
- Axios for HTTP

## Quick start

You need Node.js 16+ and npm, plus the ThreatSentinel backend running on `http://localhost:8000`.

```bash
cd frontend
npm install
npm start
```

Then open `http://localhost:3000`.

### Environment configuration

Create a `.env` file in the frontend directory:

```env
VITE_API_URL=http://localhost:8000
```

## Project structure

```
frontend/
├── public/                 # Static assets
├── src/
│   ├── components/         # Reusable UI components
│   │   ├── Dashboard/      # Dashboard-specific components
│   │   ├── Investigations/ # Investigation management
│   │   ├── Layout/         # Layout and navigation
│   │   └── Common/         # Shared components
│   ├── pages/              # Page components
│   ├── context/            # React context providers
│   ├── hooks/              # Custom React hooks
│   ├── utils/              # Utility functions
│   └── styles/             # Global styles and themes
├── package.json
└── tailwind.config.js      # Tailwind configuration
```

## Key components

Dashboard: MetricCard, ThreatActivityChart, QuickActions, SystemStatus, RecentInvestigations.

Investigations: InvestigationForm, InvestigationTable, InvestigationDetail, InvestigationTimeline.

Layout: Layout (main shell with sidebar), Navigation, Header.

## API integration

The frontend talks to the backend over REST for CRUD operations and WebSockets for live updates. React Query handles caching; errors surface as toasts with retry feedback.

## Development

Available scripts:

- `npm start`: development server
- `npm run build`: production build
- `npm test`: test suite
- `npm eject`: eject from Create React App

ESLint and Prettier handle linting and formatting. Jest and React Testing Library cover tests.

## Deployment

Production build:

```bash
npm run build
npx serve -s build
```

Docker (multi-stage build, served by nginx as an unprivileged container):

```bash
docker build -t threatsentinel-frontend .
docker run -p 3000:8080 threatsentinel-frontend
```

Pass `--build-arg VITE_API_URL=...` to point the dashboard at a backend other than `http://localhost:8000`.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

Check the main ThreatSentinel documentation, review the API docs, or open an issue on GitHub.

## License

MIT. See the LICENSE file for details.
