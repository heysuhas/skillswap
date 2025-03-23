import { ReactNode } from "react";

interface AvatarIconProps {
  icon: ReactNode;
  className?: string;
}

export function AvatarIcon({ icon, className = "" }: AvatarIconProps) {
  return (
    <div className={`flex-shrink-0 w-10 h-10 rounded-full bg-primary-100 flex items-center justify-center text-primary-600 ${className}`}>
      {icon}
    </div>
  );
}
