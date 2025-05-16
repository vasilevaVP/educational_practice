$(document).ready(function () {
  $(".slider").slick({
    slidesToShow: 1,
    slidesToScroll: 1,
    autoplay: true,
    autoplaySpeed: 2000,
    infinite: true,
    speed: 500,

    arrows: false, // Отключаем стандартные стрелки
    dots: false,
    swipe: true,
    touchMove: true,
    responsive: [
      {
        breakpoint: 768,
        settings: {
          arrows: false,
          dots: false,
        },
      },
    ],
  });

  // Обработчики событий для кастомных стрелок (только для десктопа)
  if (window.innerWidth > 768) {
    $(".arrow.prev").click(function () {
      $(".slider").slick("slickPrev");
    });

    $(".arrow.next").click(function () {
      $(".slider").slick("slickNext");
    });
  }

  // Обновляем обработчики при изменении размера окна
  $(window).resize(function () {
    if (window.innerWidth <= 768) {
      $(".arrow.prev").off("click");
      $(".arrow.next").off("click");
    } else {
      $(".arrow.prev").click(function () {
        $(".slider").slick("slickPrev");
      });
      $(".arrow.next").click(function () {
        $(".slider").slick("slickNext");
      });
    }
  });
});

