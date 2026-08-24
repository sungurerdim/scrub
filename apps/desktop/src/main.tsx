import React from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";
import { App } from "./App";

const root = document.getElementById("root");
if (!root) throw new Error("the page has no root element to draw into");

createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
