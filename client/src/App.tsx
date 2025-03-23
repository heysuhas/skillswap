import { Switch, Route, useLocation } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { AuthProvider } from "./hooks/use-auth";

// Pages
import Dashboard from "@/pages/dashboard";
import Login from "@/pages/auth/login";
import Register from "@/pages/auth/register";
import Profile from "@/pages/profile";
import Matches from "@/pages/matches";
import Messages from "@/pages/messages";
import Sessions from "@/pages/sessions";
import NotFound from "@/pages/not-found";

// Route guard for protected routes
const ProtectedRoute = ({ component: Component, ...rest }: { component: React.ComponentType<any>, [key: string]: any }) => {
  const [location, setLocation] = useLocation();
  const { isAuthenticated, isLoading } = useAuth();
  
  if (isLoading) {
    return <div className="min-h-screen flex items-center justify-center">Loading...</div>;
  }
  
  if (!isAuthenticated) {
    setLocation('/login');
    return null;
  }
  
  return <Component {...rest} />;
};

const PublicRoute = ({ component: Component, ...rest }: { component: React.ComponentType<any>, [key: string]: any }) => {
  const [location, setLocation] = useLocation();
  const { isAuthenticated, isLoading } = useAuth();
  
  if (isLoading) {
    return <div className="min-h-screen flex items-center justify-center">Loading...</div>;
  }
  
  if (isAuthenticated) {
    setLocation('/');
    return null;
  }
  
  return <Component {...rest} />;
};

import { useAuth } from "./hooks/use-auth";

function Router() {
  const { isAuthenticated, isLoading } = useAuth();
  const [location, setLocation] = useLocation();

  // Global loading state
  if (isLoading) {
    return <div className="min-h-screen flex items-center justify-center">Loading...</div>;
  }

  // Redirect to login if not authenticated and not on auth pages
  if (!isAuthenticated && !location.startsWith('/login') && !location.startsWith('/register')) {
    setLocation('/login');
    return null;
  }

  return (
    <Switch>
      <Route path="/" component={Dashboard} />
      <Route path="/login" component={Login} />
      <Route path="/register" component={Register} />
      <Route path="/profile" component={Profile} />
      <Route path="/matches" component={Matches} />
      <Route path="/messages/:id?" component={Messages} />
      <Route path="/sessions" component={Sessions} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <Router />
        <Toaster />
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
