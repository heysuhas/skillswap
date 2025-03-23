import { ReactNode } from "react";

interface StatCardProps {
  title: string;
  value: number;
  icon: ReactNode;
  color?: 'primary' | 'secondary' | 'accent' | 'default';
}

export function StatCard({ title, value, icon, color = 'primary' }: StatCardProps) {
  const bgColors = {
    primary: 'bg-primary-50 text-primary-600',
    secondary: 'bg-emerald-50 text-secondary-500',
    accent: 'bg-amber-50 text-amber-500',
    default: 'bg-slate-100 text-slate-600',
  };

  return (
    <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-sm">
      <div className="flex items-center">
        <div className={`p-2 rounded-md ${bgColors[color]}`}>
          {icon}
        </div>
        <div className="ml-3">
          <p className="text-sm font-medium text-slate-500">{title}</p>
          <p className="text-2xl font-semibold text-slate-800">{value}</p>
        </div>
      </div>
    </div>
  );
}
