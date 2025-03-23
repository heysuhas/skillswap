import { Link, useLocation } from "wouter";
import { LayoutDashboard, Users, MessageSquare, Calendar } from "lucide-react";

export default function MobileNav() {
  const [location] = useLocation();

  const isActive = (path: string) => {
    if (path === '/messages' && location.startsWith('/messages/')) {
      return true;
    }
    return location === path;
  };

  return (
    <div className="md:hidden flex items-center justify-around py-3 bg-white border-t border-slate-200">
      <Link href="/">
        <a className={`flex flex-col items-center ${isActive('/') ? 'text-primary-600' : 'text-slate-400'}`}>
          <LayoutDashboard className="h-5 w-5" />
          <span className="text-xs mt-1">Dashboard</span>
        </a>
      </Link>
      <Link href="/matches">
        <a className={`flex flex-col items-center ${isActive('/matches') ? 'text-primary-600' : 'text-slate-400'}`}>
          <Users className="h-5 w-5" />
          <span className="text-xs mt-1">Matches</span>
        </a>
      </Link>
      <Link href="/messages">
        <a className={`flex flex-col items-center ${isActive('/messages') ? 'text-primary-600' : 'text-slate-400'}`}>
          <MessageSquare className="h-5 w-5" />
          <span className="text-xs mt-1">Messages</span>
        </a>
      </Link>
      <Link href="/sessions">
        <a className={`flex flex-col items-center ${isActive('/sessions') ? 'text-primary-600' : 'text-slate-400'}`}>
          <Calendar className="h-5 w-5" />
          <span className="text-xs mt-1">Sessions</span>
        </a>
      </Link>
    </div>
  );
}
