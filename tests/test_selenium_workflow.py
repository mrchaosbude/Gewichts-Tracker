import os
import time
import multiprocessing
import pytest

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.options import Options
except ImportError:
    webdriver = None

from app import app, db

PORT = 5001

@pytest.fixture(scope="module")
def live_server():
    if webdriver is None:
        pytest.skip("Selenium not available")
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
    app.config['TESTING'] = True
    def run_app():
        with app.app_context():
            db.drop_all()
            db.create_all()
        app.run(port=PORT)
    proc = multiprocessing.Process(target=run_app)
    proc.start()
    time.sleep(2)
    yield f"http://localhost:{PORT}"
    proc.terminate()
    proc.join()
    if os.path.exists('test.db'):
        os.remove('test.db')


def register(driver, base, username, password):
    driver.get(f"{base}/register")
    driver.find_element(By.NAME, "username").send_keys(username)
    driver.find_element(By.NAME, "password").send_keys(password)
    driver.find_element(By.NAME, "confirm").send_keys(password)
    driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()


def login(driver, base, username, password):
    driver.get(f"{base}/login")
    driver.find_element(By.NAME, "username").send_keys(username)
    driver.find_element(By.NAME, "password").send_keys(password)
    driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()


def test_full_workflow(live_server):
    options = Options()
    options.add_argument("--headless")
    driver = webdriver.Chrome(options=options)
    driver.implicitly_wait(3)
    base = live_server

    # Account 1 anlegen und einloggen
    register(driver, base, "user1", "pw1")
    login(driver, base, "user1", "pw1")

    # Template Trainingsplan erstellen
    driver.find_element(By.LINK_TEXT, "Template Trainingspl\u00e4ne verwalten").click()
    driver.find_element(By.LINK_TEXT, "Neuen Template Trainingsplan erstellen").click()
    driver.find_element(By.NAME, "title").send_keys("Plan1")
    driver.find_element(By.NAME, "description").send_keys("Beschreibung")
    driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

    # \u00dcbung hinzuf\u00fcgen
    driver.find_element(By.LINK_TEXT, "\u00dcbung hinzuf\u00fcgen").click()
    driver.find_element(By.NAME, "name").send_keys("Bankdr\u00fccken")
    driver.find_element(By.NAME, "description").send_keys("Brust")
    driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

    # Bearbeiten
    driver.find_element(By.LINK_TEXT, "Bearbeiten").click()
    title_field = driver.find_element(By.NAME, "title")
    title_field.clear()
    title_field.send_keys("Plan1 ge\u00e4ndert")
    driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

    # Sichtbarkeit umschalten (Unsichtbar)
    driver.find_element(By.XPATH, "//form/button[contains(text(), 'Unsichtbar')]").click()

    driver.find_element(By.LINK_TEXT, "Logout").click()

    # Account 2 anlegen und einloggen
    register(driver, base, "user2", "pw2")
    login(driver, base, "user2", "pw2")
    driver.find_element(By.LINK_TEXT, "Vorlagen ansehen").click()
    assert "Plan1 ge\u00e4ndert" not in driver.page_source
    driver.find_element(By.LINK_TEXT, "Logout").click()

    # Als user1 wieder einloggen und sichtbar schalten
    login(driver, base, "user1", "pw1")
    driver.find_element(By.LINK_TEXT, "Template Trainingspl\u00e4ne verwalten").click()
    driver.find_element(By.XPATH, "//form/button[contains(text(), 'Sichtbar')]").click()
    driver.find_element(By.LINK_TEXT, "Logout").click()

    # user2 sieht jetzt die Vorlage
    login(driver, base, "user2", "pw2")
    driver.find_element(By.LINK_TEXT, "Vorlagen ansehen").click()
    assert "Plan1 ge\u00e4ndert" in driver.page_source

    # Trainingsplan erstellen, \u00dcbung hinzuf\u00fcgen und Sessions anlegen
    driver.find_element(By.LINK_TEXT, "Logout").click()
    login(driver, base, "user1", "pw1")
    driver.find_element(By.LINK_TEXT, "Neuen Trainingsplan erstellen").click()
    driver.find_element(By.NAME, "title").send_keys("TP1")
    driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()
    driver.find_element(By.LINK_TEXT, "\u00dcbung hinzuf\u00fcgen").click()
    driver.find_element(By.NAME, "name").send_keys("Bankdr\u00fccken")
    driver.find_element(By.NAME, "description").send_keys("Brust")
    driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()
    driver.find_element(By.LINK_TEXT, "Details").click()
    for i in range(2):
        driver.find_element(By.LINK_TEXT, "Neuen Satz hinzuf\u00fcgen").click()
        driver.find_element(By.NAME, "repetitions").clear()
        driver.find_element(By.NAME, "repetitions").send_keys("10")
        driver.find_element(By.NAME, "weight").clear()
        driver.find_element(By.NAME, "weight").send_keys(str(50 + i * 5))
        driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

    driver.find_element(By.LINK_TEXT, "Zur\u00fcck").click()
    driver.find_element(By.LINK_TEXT, "Zur\u00fcck").click()

    # Zweiten Trainingsplan mit gleicher \u00dcbung
    driver.find_element(By.LINK_TEXT, "Neuen Trainingsplan erstellen").click()
    driver.find_element(By.NAME, "title").send_keys("TP2")
    driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()
    driver.find_element(By.LINK_TEXT, "\u00dcbung hinzuf\u00fcgen").click()
    select = driver.find_element(By.NAME, "existing_exercise_id")
    options = select.find_elements(By.TAG_NAME, "option")
    options[1].click()  # erste vorhandene \u00dcbung w\u00e4hlen
    driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()
    sessions_text = driver.find_element(By.CLASS_NAME, "session-list").text
    assert "50 kg" in sessions_text
    assert "55 kg" in sessions_text
    driver.quit()
