"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/hooks/use-auth";
import { 
  Shield, 
  LayoutDashboard, 
  UploadCloud, 
  History, 
  Users, 
  LogOut, 
  Menu, 
  X,
  ChevronLeft,
  ChevronRight
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/utils/cn";

export function Sidebar() {
  const pathname = usePathname();
  const { user, logout, isAdmin, isAuthenticated } = useAuth();
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  if (!isAuthenticated) return null;

  const links = [
    { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
    { name: "Scan Binary", href: "/scan", icon: UploadCloud },
    { name: "Scan History", href: "/history", icon: History },
  ];

  if (isAdmin) {
    links.push({ name: "Admin Portal", href: "/admin", icon: Users });
  }

  const sidebarVariants = {
    expanded: { width: 260 },
    collapsed: { width: 80 }
  };

  return (
    <>
      {/* Mobile Menu trigger */}
      <div className="lg:hidden fixed top-4 left-4 z-50">
        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          className="p-2 rounded-md bg-secondary text-foreground border border-border"
        >
          {mobileOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </div>

      {/* Mobile Drawer */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ x: "-100%" }}
            animate={{ x: 0 }}
            exit={{ x: "-100%" }}
            transition={{ type: "spring", bounce: 0.15 }}
            className="lg:hidden fixed inset-y-0 left-0 z-40 w-72 glass-panel flex flex-col p-6 shadow-2xl border-r border-border"
          >
            <div className="flex items-center gap-3 mb-10 mt-6">
              <Shield className="text-primary animate-pulse" size={32} />
              <span className="font-extrabold text-xl bg-gradient-to-r from-primary to-indigo-400 bg-clip-text text-transparent">
                MALGUARD AI
              </span>
            </div>

            <nav className="flex-1 space-y-2">
              {links.map((link) => {
                const isActive = pathname === link.href;
                return (
                  <Link
                    key={link.name}
                    href={link.href}
                    onClick={() => setMobileOpen(false)}
                    className={cn(
                      "flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all",
                      isActive
                        ? "bg-primary text-primary-foreground glow-blue"
                        : "text-muted-foreground hover:bg-secondary hover:text-foreground"
                    )}
                  >
                    <link.icon size={18} />
                    <span>{link.name}</span>
                  </Link>
                );
              })}
            </nav>

            <div className="border-t border-border pt-6 mt-auto">
              <div className="flex flex-col gap-2 mb-4">
                <span className="text-xs text-muted-foreground font-semibold">LOGGED IN AS</span>
                <span className="text-sm truncate font-medium text-foreground">{user?.email}</span>
                <span className="text-[10px] uppercase font-bold text-primary w-fit bg-primary/10 px-2 py-0.5 rounded-full border border-primary/20">
                  {user?.role}
                </span>
              </div>
              <button
                onClick={() => {
                  logout();
                  setMobileOpen(false);
                }}
                className="flex items-center gap-3 w-full px-4 py-3 rounded-lg text-sm font-medium text-rose-400 hover:bg-rose-500/10 hover:text-rose-300 transition-all border border-transparent hover:border-rose-500/20"
              >
                <LogOut size={18} />
                <span>Log Out</span>
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Desktop Sidebar */}
      <motion.div
        animate={isCollapsed ? "collapsed" : "expanded"}
        variants={sidebarVariants}
        transition={{ type: "spring", stiffness: 300, damping: 30 }}
        className="hidden lg:flex flex-col relative inset-y-0 z-30 h-screen glass-panel border-r border-border p-6 shadow-xl"
      >
        <div className="flex items-center gap-3 mb-10 mt-2 overflow-hidden h-10">
          <Shield className="text-primary flex-shrink-0 animate-pulse" size={28} />
          {!isCollapsed && (
            <motion.span
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.1 }}
              className="font-extrabold text-lg bg-gradient-to-r from-primary to-indigo-400 bg-clip-text text-transparent tracking-wider whitespace-nowrap"
            >
              MALGUARD AI
            </motion.span>
          )}
        </div>

        <nav className="flex-1 space-y-2">
          {links.map((link) => {
            const isActive = pathname === link.href;
            return (
              <Link
                key={link.name}
                href={link.href}
                className={cn(
                  "flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all relative overflow-hidden",
                  isActive
                    ? "bg-primary text-primary-foreground glow-blue"
                    : "text-muted-foreground hover:bg-secondary hover:text-foreground"
                )}
              >
                <link.icon size={18} className="flex-shrink-0" />
                {!isCollapsed && (
                  <motion.span
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.1 }}
                  >
                    {link.name}
                  </motion.span>
                )}
              </Link>
            );
          })}
        </nav>

        {/* Collapse Toggle Trigger Button */}
        <button
          onClick={() => setIsCollapsed(!isCollapsed)}
          className="absolute -right-3 top-1/2 -translate-y-1/2 bg-secondary border border-border text-foreground hover:text-primary rounded-full p-1 cursor-pointer shadow-md hover:scale-105 active:scale-95 transition-transform"
        >
          {isCollapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
        </button>

        <div className="border-t border-border pt-6 mt-auto">
          {!isCollapsed ? (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.1 }}
            >
              <div className="flex flex-col gap-1 mb-4 overflow-hidden">
                <span className="text-[10px] text-muted-foreground font-semibold">LOGGED IN AS</span>
                <span className="text-sm truncate font-medium text-foreground" title={user?.email}>
                  {user?.email}
                </span>
                <span className="text-[9px] uppercase font-bold text-primary w-fit bg-primary/10 px-2 py-0.5 rounded-full border border-primary/20">
                  {user?.role}
                </span>
              </div>
              <button
                onClick={logout}
                className="flex items-center gap-3 w-full px-4 py-3 rounded-lg text-sm font-medium text-rose-400 hover:bg-rose-500/10 hover:text-rose-300 transition-all border border-transparent hover:border-rose-500/20"
              >
                <LogOut size={18} className="flex-shrink-0" />
                <span>Log Out</span>
              </button>
            </motion.div>
          ) : (
            <button
              onClick={logout}
              className="flex items-center justify-center w-full py-3 rounded-lg text-rose-400 hover:bg-rose-500/10 hover:text-rose-300 transition-all border border-transparent hover:border-rose-500/20"
              title="Log Out"
            >
              <LogOut size={18} />
            </button>
          )}
        </div>
      </motion.div>
    </>
  );
}
