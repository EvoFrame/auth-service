from fastapi import Query
from pydantic import BaseModel


class PagedResponse[T](BaseModel):
    items: list[T]
    total: int
    page: int
    page_size: int
    pages: int


def pagination_params(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> tuple[int, int]:
    """FastAPI dependency that parses pagination query parameters.

    Args:
        page: 1-based page number (default: 1).
        page_size: Number of items per page, between 1 and 100 (default: 20).

    Returns:
        A tuple of (page, page_size).
    """
    return page, page_size


def paginate[T](items: list[T], total: int, page: int, page_size: int) -> PagedResponse[T]:
    """Wrap a page of items in a PagedResponse with computed page count.

    Args:
        items: The pre-sliced list of items for the current page.
        total: Total number of items across all pages.
        page: Current 1-based page number.
        page_size: Number of items per page.

    Returns:
        A PagedResponse containing metadata and the current page's items.
    """
    return PagedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=-(-total // page_size),  # ceil division
    )
