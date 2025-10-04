(function () {
  function setupDashboardDropdown() {
    var toggle = document.getElementById('dashboardActionsDropdown');
    if (!toggle) {
      return;
    }

    var menu = toggle.nextElementSibling;
    if (!menu || !menu.classList.contains('dropdown-menu')) {
      return;
    }

    function closeMenu() {
      menu.classList.remove('show');
      toggle.setAttribute('aria-expanded', 'false');
    }

    toggle.addEventListener('click', function (event) {
      event.preventDefault();
      event.stopPropagation();
      var isOpen = menu.classList.contains('show');
      if (isOpen) {
        closeMenu();
      } else {
        menu.classList.add('show');
        toggle.setAttribute('aria-expanded', 'true');
      }
    });

    document.addEventListener('click', function (event) {
      if (!menu.contains(event.target) && !toggle.contains(event.target)) {
        closeMenu();
      }
    });

    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape') {
        closeMenu();
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setupDashboardDropdown);
  } else {
    setupDashboardDropdown();
  }
})();
