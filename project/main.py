from flask import Blueprint, render_template, request, flash, redirect, url_for, send_file, abort
from flask_login import login_required, current_user

from project.utils import file_signature_valid
from . import db, env
from .models import Image, User, Evaluation
from .config import ALLOWED_FILETYPES
from .utils import is_bot
from .crypto import cipher
import base64
from datetime import datetime
import io

main = Blueprint("main", __name__)


@main.route("/")
def index():
    return render_template("index.html")


@main.route("/profile")
@login_required
def profile():
    return render_template("profile.html", name=current_user.username)

@main.route("/password-policy")
def password_policy():
    return render_template("password_policy.html")



@main.route("/request-evaluation", methods=["GET"])
@login_required
def request_evaluation():
    # Get user's previous evaluations
    previous_evaluations = Evaluation.query.filter_by(user_id=current_user.id).order_by(Evaluation.created_at.desc()).all()
    
    return render_template(
        "request_evaluation.html", 
        previous_evaluations=previous_evaluations,
        captcha_sitekey=env['RECAPTCHA_PUBLIC_KEY']
    )

@main.route("/request-evaluation", methods=["POST"])
@login_required
def submit_evaluation():
    if is_bot(request):
        flash("Invalid Captcha")
        return redirect(url_for('main.request_evaluation'))

    item_description = request.form.get("item_description")
    contact_preference = request.form.get("contact_preference")
    contact_time = request.form.get("contact_time") if contact_preference == "phone" else None
    
    # Handle multiple photo uploads
    photos = request.files.getlist("item_photos")
    photo_ids = []
    
    for photo in photos:
        if photo:
            extension = photo.filename.split('.')[-1]
            
            if extension not in ALLOWED_FILETYPES:
                flash(f"{extension} files are not allowed!")
                return redirect(url_for("main.request_evaluation"))

            image_data = photo.read()
            if not file_signature_valid(extension, image_data):
                flash("Sorry, that file is invalid")
                return redirect(url_for("main.request_evaluation"))

            new_image = Image(
                posted_by=current_user.id,
                filetype=extension,
                image=cipher.encrypt(image_data),
                comments="Evaluation request photo"
            )
            db.session.add(new_image)
            db.session.flush()
            photo_ids.append(str(new_image.id))
    
    new_evaluation = Evaluation(
        user_id=current_user.id,
        item_description=item_description,
        item_photos=",".join(photo_ids),
        contact_preference=contact_preference,
        contact_time=contact_time,
        status="pending"
    )
    
    db.session.add(new_evaluation)
    db.session.commit()
    
    flash("Your evaluation request has been submitted successfully!")
    return redirect(url_for("main.request_evaluation"))

@main.route("/evaluation/<int:eval_id>")
@login_required
def view_evaluation(eval_id):
    evaluation = Evaluation.query.get_or_404(eval_id)
    
    # Ensure user can only view their own evaluations
    if evaluation.user_id != current_user.id and not current_user.is_admin:
        flash("You don't have permission to view this evaluation")
        return redirect(url_for("main.profile"))
    
    # Get the photos
    photo_ids = evaluation.item_photos.split(",") if evaluation.item_photos else []
    photos = Image.query.filter(Image.id.in_(photo_ids)).all() if photo_ids else []
    
    return render_template(
        "view_evaluation.html",
        evaluation=evaluation,
        photos=photos
    )


@main.route("/evaluations")
@login_required
def evaluations():
    # Do not show the page if the user isn't an admin
    if not current_user.is_admin:
        return redirect(url_for("main.profile"))

    evaluations = Evaluation.query.all()
    evaluation_data = []
    
    for eval in evaluations:
        user = User.query.get(eval.user_id)
        photo_ids = eval.item_photos.split(",") if eval.item_photos else []
        photos = []
        
        for photo_id in photo_ids:
            try:
                image = Image.query.get(int(photo_id))
                if image:
                    decrypted_image = cipher.decrypt(image.image)
                    photos.append({
                        'id': image.id,
                        'data': base64.b64encode(decrypted_image).decode()
                    })
            except Exception as e:
                logger.error(f"Failed to process image {photo_id}: {str(e)}")
        
        evaluation_data.append({
            'evaluation': eval,
            'user': user,
            'photos': photos
        })

    return render_template("evaluations.html", evaluations=evaluation_data)

@main.route("/image/<int:image_id>")
@login_required
def get_image(image_id):
    image = Image.query.get_or_404(image_id)
    
    # Check if user has permission to view this image
    if image.posted_by != current_user.id and not current_user.is_admin:
        abort(403)
    
    # Decrypt the image before sending
    try:
        decrypted_image = cipher.decrypt(image.image)
        return send_file(
            io.BytesIO(decrypted_image),
            mimetype=f'image/{image.filetype}',
            as_attachment=False
        )
    except Exception as e:
        logger.error(f"Failed to decrypt image: {str(e)}")
        abort(500)
