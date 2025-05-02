
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Index from "./pages/Index";
import GettingStarted from "./pages/GettingStarted";
import Methodology from "./pages/Methodology";
import Languages from "./pages/Languages";
import DatabaseSecurity from "./pages/DatabaseSecurity";
import Tools from "./pages/Tools";
import Resources from "./pages/Resources";
import Contact from "./pages/Contact";
import NotFound from "./pages/NotFound";
import WebPenetrationTesting from "./pages/WebPenetrationTesting";

// Import language pages
import JavaScript from "./pages/languages/JavaScript";
import Java from "./pages/languages/Java";
import Python from "./pages/languages/Python";
import CSharp from "./pages/languages/CSharp";
import PHP from "./pages/languages/PHP";
import NodeJs from "./pages/languages/NodeJs";
import ReactPage from "./pages/languages/React";
import GolangPage from "./pages/languages/Golang";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Index />} />
          <Route path="/getting-started" element={<GettingStarted />} />
          <Route path="/methodology" element={<Methodology />} />
          <Route path="/languages" element={<Languages />} />
          <Route path="/database-security" element={<DatabaseSecurity />} />
          <Route path="/web-penetration-testing" element={<WebPenetrationTesting />} />
          <Route path="/tools" element={<Tools />} />
          <Route path="/resources" element={<Resources />} />
          <Route path="/contact" element={<Contact />} />
          
          {/* Language-specific routes */}
          <Route path="/languages/javascript" element={<JavaScript />} />
          <Route path="/languages/java" element={<Java />} />
          <Route path="/languages/python" element={<Python />} />
          <Route path="/languages/csharp" element={<CSharp />} />
          <Route path="/languages/php" element={<PHP />} />
          <Route path="/languages/nodejs" element={<NodeJs />} />
          <Route path="/languages/react" element={<ReactPage />} />
          <Route path="/languages/golang" element={<GolangPage />} />
          
          {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
