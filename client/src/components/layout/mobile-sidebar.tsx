import { useState, useEffect } from "react";
import { Link, useLocation } from "wouter";
import { useAuth } from "@/hooks/use-auth";
import { 
  LayoutDashboard, 
  User, 
  Users, 
  MessageSquare, 
  Calendar, 
  Settings, 
  LogOut,
  Menu,
  X
} from "lucide-react";

export default function MobileSidebar() {
  const [isOpen, setIsOpen] = useState(false);
  const [location] = useLocation();
  const { user, logout } = useAuth();

  // Close mobile menu when navigating
  useEffect(() => {
    setIsOpen(false);
  }, [location]);

  const isActive = (path: string) => {
    return location === path;
  };

  const toggleMenu = () => {
    setIsOpen(!isOpen);
  };

  return (
    <>
      {/* Mobile Header */}
      <header className="md:hidden flex items-center justify-between px-4 h-16 border-b border-slate-200 bg-white">
        <button className="text-slate-500" onClick={toggleMenu}>
          <Menu className="h-6 w-6" />
        </button>
        <div className="flex items-center space-x-2">
          <svg className="w-7 h-7 text-primary-600" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M15 5L12 2M12 2L9 5M12 2V8M7.2 10.6C6.44699 10.6 5.82446 11.2225 5.82446 11.9755C5.82446 12.3397 5.99276 12.6711 6.25945 12.9041C6.56933 13.1755 7.00293 13.493 7.55631 13.9634C8.13122 14.455 8.49897 14.8939 8.75629 15.3398C8.99721 15.7596 9.12446 16.2274 9.12446 16.825C9.12446 18.3302 7.89966 19.5 6.42446 19.5C5.11928 19.5 3.99732 18.7073 3.67119 17.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            <path d="M16.8 10.6C17.553 10.6 18.1755 11.2225 18.1755 11.9755C18.1755 12.3397 18.0072 12.6711 17.7406 12.9041C17.4307 13.1755 16.9971 13.493 16.4437 13.9634C15.8688 14.455 15.501 14.8939 15.2437 15.3398C15.0028 15.7596 14.8755 16.2274 14.8755 16.825C14.8755 18.3302 16.1003 19.5 17.5755 19.5C18.8807 19.5 20.0027 18.7073 20.3288 17.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
          <h1 className="text-lg font-semibold text-primary-600">SkillSwap</h1>
        </div>
        <Link href="/messages">
          <a className="text-slate-500">
            <MessageSquare className="h-6 w-6" />
          </a>
        </Link>
      </header>
      
      {/* Mobile Menu (Slide-over) */}
      <div className={`fixed inset-0 z-40 ${isOpen ? 'block' : 'hidden'}`}>
        <div 
          className="fixed inset-0 bg-black/20 backdrop-blur-sm"
          onClick={() => setIsOpen(false)}
        ></div>
        <div className={`fixed inset-y-0 left-0 w-64 bg-white shadow-lg transform ${isOpen ? 'translate-x-0' : '-translate-x-full'} transition-transform duration-300 ease-in-out`}>
          {/* Mobile menu content */}
          <div className="flex items-center justify-between px-4 h-16 border-b border-slate-200">
            <div className="flex items-center space-x-2">
              <svg className="w-7 h-7 text-primary-600" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M15 5L12 2M12 2L9 5M12 2V8M7.2 10.6C6.44699 10.6 5.82446 11.2225 5.82446 11.9755C5.82446 12.3397 5.99276 12.6711 6.25945 12.9041C6.56933 13.1755 7.00293 13.493 7.55631 13.9634C8.13122 14.455 8.49897 14.8939 8.75629 15.3398C8.99721 15.7596 9.12446 16.2274 9.12446 16.825C9.12446 18.3302 7.89966 19.5 6.42446 19.5C5.11928 19.5 3.99732 18.7073 3.67119 17.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M16.8 10.6C17.553 10.6 18.1755 11.2225 18.1755 11.9755C18.1755 12.3397 18.0072 12.6711 17.7406 12.9041C17.4307 13.1755 16.9971 13.493 16.4437 13.9634C15.8688 14.455 15.501 14.8939 15.2437 15.3398C15.0028 15.7596 14.8755 16.2274 14.8755 16.825C14.8755 18.3302 16.1003 19.5 17.5755 19.5C18.8807 19.5 20.0027 18.7073 20.3288 17.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              <h1 className="text-lg font-semibold text-primary-600">SkillSwap</h1>
            </div>
            <button className="text-slate-500" onClick={() => setIsOpen(false)}>
              <X className="h-6 w-6" />
            </button>
          </div>
          
          <nav className="px-2 py-4 space-y-1">
            <Link href="/">
              <a className={`flex items-center px-4 py-2 text-sm font-medium rounded-md ${isActive('/') ? 'bg-primary-50 text-primary-700' : 'text-slate-600 hover:bg-slate-100'}`}>
                <LayoutDashboard className="mr-3 h-5 w-5" />
                Dashboard
              </a>
            </Link>
            <Link href="/profile">
              <a className={`flex items-center px-4 py-2 text-sm font-medium rounded-md ${isActive('/profile') ? 'bg-primary-50 text-primary-700' : 'text-slate-600 hover:bg-slate-100'}`}>
                <User className="mr-3 h-5 w-5" />
                Profile
              </a>
            </Link>
            <Link href="/matches">
              <a className={`flex items-center px-4 py-2 text-sm font-medium rounded-md ${isActive('/matches') ? 'bg-primary-50 text-primary-700' : 'text-slate-600 hover:bg-slate-100'}`}>
                <Users className="mr-3 h-5 w-5" />
                Matches
              </a>
            </Link>
            <Link href="/messages">
              <a className={`flex items-center px-4 py-2 text-sm font-medium rounded-md ${isActive('/messages') || location.startsWith('/messages/') ? 'bg-primary-50 text-primary-700' : 'text-slate-600 hover:bg-slate-100'}`}>
                <MessageSquare className="mr-3 h-5 w-5" />
                Messages
              </a>
            </Link>
            <Link href="/sessions">
              <a className={`flex items-center px-4 py-2 text-sm font-medium rounded-md ${isActive('/sessions') ? 'bg-primary-50 text-primary-700' : 'text-slate-600 hover:bg-slate-100'}`}>
                <Calendar className="mr-3 h-5 w-5" />
                Sessions
              </a>
            </Link>
            <Link href="/profile">
              <a className={`flex items-center px-4 py-2 text-sm font-medium rounded-md ${isActive('/settings') ? 'bg-primary-50 text-primary-700' : 'text-slate-600 hover:bg-slate-100'}`}>
                <Settings className="mr-3 h-5 w-5" />
                Settings
              </a>
            </Link>
          </nav>
          
          <div className="absolute bottom-0 left-0 right-0 border-t border-slate-200">
            <div className="flex items-center p-4">
              <div className="w-10 h-10 rounded-full bg-primary-100 flex items-center justify-center text-primary-600">
                {user?.username?.charAt(0).toUpperCase()}
              </div>
              <div className="ml-3">
                <p className="text-sm font-medium text-slate-700">{user?.username}</p>
                <p className="text-xs text-slate-500">{user?.email}</p>
              </div>
              <button 
                onClick={logout}
                className="ml-auto text-slate-400 hover:text-slate-500"
              >
                <LogOut className="h-5 w-5" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
