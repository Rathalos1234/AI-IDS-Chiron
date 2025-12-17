import { render, screen, fireEvent } from "@testing-library/react";
import ThemeToggle from "../ThemeToggle";

test("theme toggle button can be clicked", () => {
  render(<ThemeToggle />);

  const button = screen.getByRole("button");
  fireEvent.click(button);

});
