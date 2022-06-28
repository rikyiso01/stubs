from io import BytesIO
from pathlib import Path
from typing import Any
from .utils import Rect
from arsenic.constants import SelectorType

class Element:
    """A web element. You should not create instances of this class yourself, instead use Session.get_element() or Session.get_elements()."""

    async def get_text(self) -> str:
        """Coroutine to get the text of this element."""
    async def send_keys(self, keys: str) -> None:
        """Coroutine to send a sequence of keys to this element. Useful for text inputs.

        - keys: The keys to send. Use arsenic.keys for special keys."""
    async def send_file(self, file: Path) -> None:
        """Coroutine to send a file to this element. Useful for file inputs.

        - file: The local path to the file."""
    async def clear(self) -> None:
        """Coroutine to clear this element. Useful for form inputs."""
    async def click(self) -> None:
        """Coroutine to click on this element."""
    async def is_displayed(self) -> bool:
        """Coroutine to check if this element is displayed or not."""
    async def is_enabled(self) -> bool:
        """Coroutine to check if this element is enabled."""
    async def get_attribute(self, name: str) -> str:
        """Coroutine which returns the value of a given attribute of this element.

        - name: Name of the attribute to get."""
    async def select_by_value(self, value: str) -> str:
        """Coroutine to select an option by value. This is useful if this element is a select input.

        - value: Value of the option to select."""
    async def get_rect(self) -> Rect:
        """Coroutine to get the location and size of the element."""
    async def get_element(
        self, selector: str, selector_type: SelectorType = ...
    ) -> Element:
        """Coroutine to get a child element of this element via CSS selector.

        - selector: CSS selector."""
    async def get_elements(
        self, selector: str, selector_type: SelectorType = ...
    ) -> list[Element]:
        """Coroutine to get a list of child elements of this element via CSS selector.

        - selector: CSS selector."""

class Session:
    """A webdriver session. You should not create instances of this class yourself, instead use arsenic.get_session() or arsenic.start_session()."""

    async def request(
        self, url: str, method: str = ..., data: dict[str, Any] = ...
    ) -> None:
        """Coroutine to perform a direct webdriver request.

        - url: URL to call.
        - method: method to use
        - data: data to send"""
    async def get(self, url: str) -> str:
        """Coroutine to navigate to a given url.

        - url: URL to navigate to."""
    async def get_url(self) -> str:
        """Coroutine to get the current URL."""
    async def get_source(self) -> str:
        """Coroutine to get the source of the current page."""
    async def get_element(
        self, selector: str, selector_type: SelectorType = ...
    ) -> Element:
        """Coroutine to get an element via CSS selector.

        - selector: CSS selector of the element."""
    async def get_elements(
        self, selector: str, selector_type: SelectorType = ...
    ) -> list[Element]:
        """Coroutine to get a list of elements via CSS selector.

        - selector: CSS selector of the elements."""
    async def wait_for_element(
        self, timeout: int, selector: str, selector_type: SelectorType = ...
    ) -> Element:
        """Coroutine like get_element(), but waits up to timeout seconds for the element to appear.

        - timeout: Timeout in seconds.
        - selector: CSS selector."""
    async def wait_for_element_gone(
        self, timeout: int, selector: str, selector_type: SelectorType = ...
    ) -> None:
        """Coroutine that waits up to timeout seconds for the element for the given CSS selector to no longer be available.

        - timeout: Timeout in seconds.
        - selector: CSS Selector."""
    async def add_cookies(
        self,
        name: str,
        value: str,
        *args: None,
        path: str = ...,
        domain: str = ...,
        secure: bool = ...,
        expiry: int = ...
    ) -> None:
        """Coroutine to set a cookie.

        - name: Name of the cookie.
        - value: Value of the cookie.
        - path: Optional, keyword-only path of the cookie.
        - domain: Optional, keyword-only domain of the cookie.
        - secure: Optional, keyword-only secure flag of the cookie.
        - expiry: Optional, keyword-only expiration of the cookie."""
    async def get_cookie(self, name: str) -> str:
        """Coroutine to get the value of a cookie.

        - name: Name of the cookie."""
    async def get_all_cookies(self) -> dict[str, str]:
        """Coroutine to get all cookies."""
    async def delete_cookie(self, name: str) -> None:
        """Coroutine to delete a specific cookie.

        - name: Name of the cookie to delete."""
    async def delete_all_cookies(self) -> None:
        """Coroutine to delete all cookies."""
    async def execute_script(self, script: str, *args: Any) -> Any:
        """Coroutine which executes a javascript script with the given arguments.

        - script: Javascript script source to execute.
        - args: Arguments to pass to the script. Must be JSON serializable."""
    async def execute_async_script(self, script: str, *args: Any) -> Any: ...
    async def set_window_size(self, width: int, height: int, handle: str = ...) -> None:
        """Coroutine to set the size of a given window.

        - width: Width in pixels.
        - height: Height in pixels.
        - handle: ID of the window."""
    async def get_window_size(self, handle: str = ...) -> tuple[int, int]:
        """Coroutine to get the size of a given window.

        - handle: ID of the window."""
    async def get_window_handle(self) -> str:
        """Coroutine to get the handle of the current window"""
    async def switch_to_window(self, handle: str) -> str:
        """Coroutine to set the handle of the current window

        - handle: ID of the window."""
    async def get_window_handles(self) -> list[str]:
        """Coroutine to get the handles of all windows"""
    async def get_alert_text(self) -> str:
        """Coroutine to return the text of an alert message."""
    async def send_alter_text(self, value: str) -> None:
        """Coroutine to send text to an alert message.

        - Value to send."""
    async def dismiss_alert(self) -> None:
        """Coroutine to dismiss an active alert."""
    async def accept_alert(self) -> None:
        """Coroutine to accept an active alert."""
    async def get_screenshot(self) -> BytesIO:
        """Coroutine to take a screenshot of the top-level browsing context’s viewport."""
    async def close(self) -> None:
        """Coroutine to close this session."""
