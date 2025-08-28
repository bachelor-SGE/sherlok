#pragma once

#include <string>

namespace ui {

// Показывает полноэкранное top-most окно, блокирующее рабочую поверхность до ввода верного пароля.
// Возвращает true, если введён правильный пароль и окно закрыто; false в иных случаях.
bool showPasswordLock(const std::string& title, const std::string& message, const std::string& requiredPassword);

}


